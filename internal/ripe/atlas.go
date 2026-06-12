// Package ripe provides a client for the RIPE Atlas API that submits
// one-off TCP/TLS reachability measurements filtered to Iranian probes.
//
// If RIPE_ATLAS_API_KEY is absent or empty, all methods degrade gracefully
// and return (false, false) — the system continues in OONI-only mode.
package ripe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	atlasBase     = "https://atlas.ripe.net/api/v2"
	pollInterval  = 15 * time.Second
	maxPollWait   = 10 * time.Minute
)

// MeasurementDefinition describes a single RIPE Atlas measurement target.
type measurementDef struct {
	Type    string `json:"type"`
	Target  string `json:"target"`
	Port    int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// probeSpec filters measurements to Iranian probes.
type probeSpec struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// createRequest is the body for POST /measurements/.
type createRequest struct {
	Definitions []measurementDef `json:"definitions"`
	Probes      []probeSpec      `json:"probes"`
	IsOneOff    bool             `json:"is_one_off"`
}

// createResponse holds the IDs of newly created measurements.
type createResponse struct {
	Measurements []int `json:"measurements"`
}

// measurementStatus is returned by GET /measurements/{id}/.
type measurementStatus struct {
	Status struct {
		ID   int    `json:"id"`
		Name string `json:"name"` // "stopped", "ongoing", etc.
	} `json:"status"`
}

// measurementResult is one probe result from GET /measurements/{id}/results/.
type measurementResult struct {
	From    string `json:"from"`
	RTTAVG  float64 `json:"avg,omitempty"`
	Result  interface{} `json:"result"`
}

// Client submits and polls RIPE Atlas measurements.
type Client struct {
	apiKey string
	hc     *http.Client
}

// New creates a Client. If apiKey is empty the client operates in no-op mode.
func New(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		hc:     &http.Client{Timeout: 30 * time.Second},
	}
}

// Enabled returns false when no API key is configured.
func (c *Client) Enabled() bool {
	return c.apiKey != ""
}

func (c *Client) jsonPost(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		atlasBase+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Key "+c.apiKey)
	return c.hc.Do(req)
}

func (c *Client) jsonGet(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, atlasBase+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Key "+c.apiKey)
	return c.hc.Do(req)
}

// Measure submits a one-off TCP reach measurement to the given host:port
// from Iranian RIPE Atlas probes, waits for completion, and returns whether
// any Iranian probe successfully reached the target.
//
// Returns (reachable bool, tested bool).
// tested == false when the API key is absent or the measurement fails to start.
func (c *Client) Measure(ctx context.Context, host string, port int) (bool, bool) {
	if !c.Enabled() {
		return false, false
	}

	// Submit measurement
	body := createRequest{
		Definitions: []measurementDef{
			{Type: "tcp", Target: host, Port: port, Protocol: "TCP"},
		},
		Probes: []probeSpec{
			{Type: "country", Value: "IR"},
		},
		IsOneOff: true,
	}

	resp, err := c.jsonPost(ctx, "/measurements/", body)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return false, false
	}

	var created createResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil || len(created.Measurements) == 0 {
		return false, false
	}
	msID := created.Measurements[0]

	// Poll until stopped
	deadline := time.Now().Add(maxPollWait)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false, false
		case <-time.After(pollInterval):
		}

		statusResp, err := c.jsonGet(ctx, fmt.Sprintf("/measurements/%d/", msID))
		if err != nil {
			continue
		}
		var ms measurementStatus
		json.NewDecoder(statusResp.Body).Decode(&ms) //nolint:errcheck
		statusResp.Body.Close()

		if ms.Status.Name == "stopped" {
			break
		}
	}

	// Fetch results
	resultsResp, err := c.jsonGet(ctx, fmt.Sprintf("/measurements/%d/results/", msID))
	if err != nil {
		return false, false
	}
	defer resultsResp.Body.Close()

	var results []measurementResult
	if err := json.NewDecoder(resultsResp.Body).Decode(&results); err != nil {
		return false, false
	}

	// Any successful result from an IR probe → reachable
	for _, r := range results {
		if r.RTTAVG > 0 {
			return true, true
		}
	}
	return false, len(results) > 0
}
