// Package ipinfo provides a thread-safe, cached client for the ipinfo.io
// free-tier API, used to resolve bridge IP addresses to their Autonomous
// System Number (ASN) and country code.
// Free tier: no API key required for under 50 000 requests/month.
package ipinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Response is the subset of the ipinfo.io JSON response we care about.
type Response struct {
	IP      string `json:"ip"`
	Org     string `json:"org"`     // e.g. "AS12880 Information Technology Company"
	Country string `json:"country"` // ISO 3166-1 alpha-2
}

// ASN extracts just the ASN string from the Org field (e.g. "AS12880").
func (r *Response) ASN() string {
	if r == nil || r.Org == "" {
		return ""
	}
	parts := strings.SplitN(r.Org, " ", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0] // "AS12880"
}

// Client is a cached, concurrency-safe ipinfo.io lookup client.
type Client struct {
	mu     sync.Mutex
	cache  map[string]*Response
	hc     *http.Client
}

// New creates a new Client with a pre-allocated cache and an HTTP client
// that enforces a total timeout per request.
func New() *Client {
	return &Client{
		cache: make(map[string]*Response),
		hc: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Lookup resolves an IP address to its ASN and country code.
// Results are cached in-memory to avoid duplicate API calls within one run.
// Returns nil if the lookup fails (network error or non-200 response).
func (c *Client) Lookup(ctx context.Context, ip string) (*Response, error) {
	if ip == "" || ip == "snowflake-broker" {
		return nil, fmt.Errorf("not a routable IP: %q", ip)
	}

	// Check cache first (fast path, no lock held during HTTP).
	c.mu.Lock()
	if cached, ok := c.cache[ip]; ok {
		c.mu.Unlock()
		return cached, nil
	}
	c.mu.Unlock()

	url := fmt.Sprintf("https://ipinfo.io/%s/json", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "TorShield-IR/1.0 (github.com/user/torshield-ir)")
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ipinfo.io returned HTTP %d for %s", resp.StatusCode, ip)
	}

	var result Response
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	c.mu.Lock()
	c.cache[ip] = &result
	c.mu.Unlock()

	return &result, nil
}
