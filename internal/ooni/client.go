// Package ooni provides a rate-limited, backoff-capable client for the OONI
// (Open Observatory of Network Interference) Measurements API.
// It queries bridge-specific measurements from Iranian probes (probe_cc=IR)
// and classifies each bridge as iran_likely_working, iran_likely_blocked,
// or iran_unknown based on anomaly flags in recent measurements.
//
// WebTunnel classification note:
//   WebTunnel bridges use HTTPS domain-fronted URLs, not bare IP:port.
//   OONI measures by input (IP address), so WebTunnel bridges almost never
//   appear in OONI data — they will always return StatusUnknown from OONI.
//   The caller (iran_tester) handles this correctly: WebTunnel bridges
//   reachable via TLS are classified as iran_likely_working (Tier-2),
//   not left as iran_unknown.
package ooni

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// OONIStatus represents the Iran-specific classification derived from OONI data.
type OONIStatus string

const (
	StatusLikelyWorking OONIStatus = "iran_likely_working"
	StatusLikelyBlocked OONIStatus = "iran_likely_blocked"
	StatusUnknown       OONIStatus = "iran_unknown"
	StatusFreqBlocked   OONIStatus = "iran_frequently_blocked"

	ooniBase        = "https://api.ooni.io/api/v1/measurements"
	recentDays      = 7
	temporalDays    = 90
	freqBlockThresh = 2.0 // anomalies per 30-day period that triggers frequently_blocked
)

// Measurement is the minimal subset of an OONI measurement result.
type Measurement struct {
	Anomaly       bool   `json:"anomaly"`
	Confirmed     bool   `json:"confirmed"`
	TestStartTime string `json:"test_start_time"`
	TestName      string `json:"test_name"`
}

// measurementsResponse is the top-level OONI API response envelope.
type measurementsResponse struct {
	Results []Measurement `json:"results"`
}

// Client is a rate-limited OONI API client.
// Rate limit: 5 req/s as per OONI guidelines.
// Backoff: exponential on HTTP 429, up to 3 retries.
type Client struct {
	hc      *http.Client
	ticker  *time.Ticker
	mu      sync.Mutex // protects ticker channel drain
	cache   map[string]*analysisResult
	cacheMu sync.Mutex
}

type analysisResult struct {
	Status         OONIStatus
	RecurrenceRate float64
	Checked        bool
}

// New creates a Client that honours a 5-requests-per-second rate limit.
func New() *Client {
	return &Client{
		hc:     &http.Client{Timeout: 30 * time.Second},
		ticker: time.NewTicker(200 * time.Millisecond), // 5 req/s
		cache:  make(map[string]*analysisResult),
	}
}

// Close releases the rate-limiting ticker.
func (c *Client) Close() {
	c.ticker.Stop()
}

// waitTick blocks until the rate-limiter permits the next request.
func (c *Client) waitTick(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ticker.C:
		return nil
	}
}

// fetch performs one HTTP GET with exponential backoff on HTTP 429.
func (c *Client) fetch(ctx context.Context, rawURL string) (*measurementsResponse, error) {
	const maxRetries = 3
	backoff := 2 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if err := c.waitTick(ctx); err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Accept", "application/json")

		resp, err := c.hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("HTTP GET: %w", err)
		}

		switch resp.StatusCode {
		case http.StatusOK:
			var data measurementsResponse
			err = json.NewDecoder(resp.Body).Decode(&data)
			resp.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("decode: %w", err)
			}
			return &data, nil

		case http.StatusTooManyRequests:
			resp.Body.Close()
			if attempt == maxRetries {
				return nil, fmt.Errorf("OONI API rate-limit exceeded after %d retries", maxRetries)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}

		default:
			resp.Body.Close()
			return nil, fmt.Errorf("OONI API HTTP %d for %s", resp.StatusCode, rawURL)
		}
	}
	return nil, fmt.Errorf("fetch exhausted retries")
}

// buildURL constructs an OONI measurements query URL.
func buildURL(ip string, since, until time.Time, limit int) string {
	params := url.Values{}
	params.Set("probe_cc", "IR")
	params.Set("input", ip)
	params.Set("limit", fmt.Sprintf("%d", limit))
	params.Set("order_by", "test_start_time")
	params.Set("since", since.Format("2006-01-02"))
	params.Set("until", until.Format("2006-01-02"))
	return ooniBase + "?" + params.Encode()
}

// Classify queries OONI for the given IP address and returns its Iran status.
//
// Two time windows are queried:
//   - Last 7 days: determines current status (likely_working / likely_blocked / unknown).
//   - Last 90 days: computes blocking recurrence rate (frequently_blocked if > 2/month).
//
// When OONI has no measurement data for the IP (empty results), the function
// returns StatusUnknown. The caller is responsible for applying transport-specific
// fallback logic — for example, WebTunnel bridges that are TLS-reachable should
// be upgraded to StatusLikelyWorking by the caller even when OONI returns Unknown.
func (c *Client) Classify(ctx context.Context, ip string) (OONIStatus, float64, bool) {
	// Cache check
	c.cacheMu.Lock()
	if cached, ok := c.cache[ip]; ok {
		c.cacheMu.Unlock()
		return cached.Status, cached.RecurrenceRate, cached.Checked
	}
	c.cacheMu.Unlock()

	now := time.Now().UTC()

	// ── Recent window (7 days) ──────────────────────────────────────────
	recentURL := buildURL(ip, now.AddDate(0, 0, -recentDays), now, 5)
	recentData, err := c.fetch(ctx, recentURL)
	if err != nil || recentData == nil {
		return StatusUnknown, 0, false
	}

	var status OONIStatus
	if len(recentData.Results) == 0 {
		// No OONI measurements for this IP from Iranian probes.
		// This is the common case for:
		//   - New bridges not yet widely used in Iran
		//   - WebTunnel bridges (OONI queries by IP, WebTunnel uses HTTPS domains)
		//   - obfs4 bridges on less common ports
		// The caller should apply transport-specific fallback logic.
		status = StatusUnknown
	} else {
		anyBlocked := false
		allClean := true
		for _, m := range recentData.Results {
			if m.Anomaly || m.Confirmed {
				anyBlocked = true
				allClean = false
			}
		}
		switch {
		case anyBlocked:
			status = StatusLikelyBlocked
		case allClean:
			status = StatusLikelyWorking
		default:
			status = StatusUnknown
		}
	}

	// ── Temporal window (90 days) ───────────────────────────────────────
	temporalURL := buildURL(ip, now.AddDate(0, 0, -temporalDays), now, 100)
	temporalData, err := c.fetch(ctx, temporalURL)

	var recurrenceRate float64
	if err == nil && temporalData != nil && len(temporalData.Results) > 0 {
		anomalyCount := 0
		for _, m := range temporalData.Results {
			if m.Anomaly || m.Confirmed {
				anomalyCount++
			}
		}
		// blocks per 30-day period
		recurrenceRate = float64(anomalyCount) / (float64(temporalDays) / 30.0)
		if recurrenceRate > freqBlockThresh {
			status = StatusFreqBlocked
		}
	}

	result := &analysisResult{
		Status:         status,
		RecurrenceRate: recurrenceRate,
		Checked:        true,
	}
	c.cacheMu.Lock()
	c.cache[ip] = result
	c.cacheMu.Unlock()

	return status, recurrenceRate, true
}
