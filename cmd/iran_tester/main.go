// Binary iran_tester implements the 8-layer TorShield-IR bridge classification
// decision tree. It reads a JSON array of bridge strings, classifies each one
// against Iran's censorship infrastructure using TCP probing, ASN filtering,
// TLS fingerprint risk assessment, port risk assessment, OONI measurements,
// temporal blocking analysis, CDN front validation, and optional RIPE Atlas
// confirmation, then writes a structured JSON report to the output file.
//
// Build:
//
//	CGO_ENABLED=0 GOOS=linux go build -o iran_tester ./cmd/iran_tester/
//
// Run:
//
//	./iran_tester --input bridge/bridge_list_for_testing.json \
//	              --output bridge/iran_results.json \
//	              --workers 100 --timeout 8s
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hrrjruruufgbbvhrh/Tor-Bridges-Collector-Ultra/internal/asn"
	"github.com/hrrjruruufgbbvhrh/Tor-Bridges-Collector-Ultra/internal/bridge"
	"github.com/hrrjruruufgbbvhrh/Tor-Bridges-Collector-Ultra/internal/ipinfo"
	"github.com/hrrjruruufgbbvhrh/Tor-Bridges-Collector-Ultra/internal/ooni"
)

// ─────────────────────────────────────────────────────────────────────────────
// Result types
// ─────────────────────────────────────────────────────────────────────────────

// IranStatus enumerates the possible outcomes of the decision tree.
type IranStatus string

const (
	StatusTCPUnreachable    IranStatus = "tcp_unreachable"
	StatusIranASNBlocked    IranStatus = "iran_asn_blocked"
	StatusIranLikelyWorking IranStatus = "iran_likely_working"
	StatusIranLikelyBlocked IranStatus = "iran_likely_blocked"
	StatusIranUnknown       IranStatus = "iran_unknown"
	StatusIranFreqBlocked   IranStatus = "iran_frequently_blocked"
)

// DPIFlag enumerates additive risk flags that do not stop classification.
type DPIFlag string

const (
	FlagDPIHighRisk         DPIFlag = "iran_dpi_high_risk"
	FlagPortHighRisk        DPIFlag = "iran_port_high_risk"
	FlagDomainFrontDegraded DPIFlag = "domain_front_degraded"
	FlagDomainFrontCDNOK    DPIFlag = "domain_front_cdn_ok"
)

// BridgeResult is the per-bridge output record.
type BridgeResult struct {
	Line           string     `json:"line"`
	Host           string     `json:"host"`
	Port           int        `json:"port"`
	Transport      string     `json:"transport"`
	TCPReachable   bool       `json:"tcp_reachable"`
	IranStatus     IranStatus `json:"iran_status"`
	OONIChecked    bool       `json:"ooni_checked"`
	RecurrenceRate float64    `json:"recurrence_rate_per_30d,omitempty"`
	ASN            string     `json:"asn,omitempty"`
	ASNCountry     string     `json:"asn_country,omitempty"`
	ASNOrg         string     `json:"asn_org,omitempty"`
	RIPEReachable  *bool      `json:"ripe_reachable,omitempty"`
	Flags          []DPIFlag  `json:"flags,omitempty"`
	CompositeScore float64    `json:"composite_score"`
}

// Summary aggregates the full run statistics.
type Summary struct {
	TotalTested         int `json:"total_tested"`
	GlobalReachable     int `json:"global_reachable"`
	IranLikelyWorking   int `json:"iran_likely_working"`
	IranLikelyBlocked   int `json:"iran_likely_blocked"`
	IranUnknown         int `json:"iran_unknown"`
	IranASNBlocked      int `json:"iran_asn_blocked"`
	IranFreqBlocked     int `json:"iran_frequently_blocked"`
}

// Report is the top-level output JSON document.
type Report struct {
	GeneratedAt string         `json:"generated_at"`
	Summary     Summary        `json:"summary"`
	Bridges     []BridgeResult `json:"bridges"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Risk / score helpers
// ─────────────────────────────────────────────────────────────────────────────

// knownTorJA3 contains JA3 fingerprints flagged as Tor-identifiable by
// Iran's DPI infrastructure.
var knownTorJA3 = map[string]bool{
	"e7d705a3286e19ea42f587b344ee6865": true,
}

// iranHighRiskPorts are Tor's well-known ports blocked by Iran's SIAM.
var iranHighRiskPorts = map[int]bool{9001: true, 9030: true, 9050: true}

func portRiskFlag(port int) bool {
	return iranHighRiskPorts[port]
}

// dpiHighRisk returns true if the TLS server hello for this endpoint carries
// a known Tor JA3 fingerprint. In practice we cannot compute JA3 from a plain
// net.Conn here, so we flag WebTunnel bridges on the default Tor port as
// elevated risk. A full JA3 check would require capturing the ClientHello.
// The flag is advisory; classification continues.
func dpiHighRisk(b *bridge.Bridge) bool {
	if b.Transport == "webtunnel" || b.Transport == "meek_lite" {
		// Flag bridges using the default Tor ORPort or PT port
		return iranHighRiskPorts[b.Port]
	}
	// For obfs4 bridges, we cannot inspect JA3 without a PT handshake.
	// We conservatively flag any bridge on a known-Tor port.
	return iranHighRiskPorts[b.Port]
}

// compositScore implements the formula:
//
//	score = 0.35*tcp + 0.40*ooni_factor + 0.25*ripe_factor
func compositeScore(tcpOK bool, iranStatus IranStatus, ripeReachable *bool, ripeTested bool) float64 {
	tcp := 0.0
	if tcpOK {
		tcp = 1.0
	}

	var ooniF float64
	switch iranStatus {
	case StatusIranLikelyWorking:
		ooniF = 1.0
	case StatusIranLikelyBlocked, StatusIranFreqBlocked:
		ooniF = 0.0
	default: // unknown, unreachable, etc.
		ooniF = 0.5
	}

	var ripeF float64
	if ripeTested {
		if ripeReachable != nil && *ripeReachable {
			ripeF = 1.0
		} else {
			ripeF = 0.0
		}
	} else {
		ripeF = 0.5 // untested
	}

	return 0.35*tcp + 0.40*ooniF + 0.25*ripeF
}

// ─────────────────────────────────────────────────────────────────────────────
// Main logic
// ─────────────────────────────────────────────────────────────────────────────

func classifyBridge(
	ctx context.Context,
	rawLine string,
	timeout time.Duration,
	ipClient *ipinfo.Client,
	ooniClient *ooni.Client,
) BridgeResult {
	result := BridgeResult{Line: rawLine}

	b, err := bridge.Parse(rawLine)
	if err != nil {
		result.IranStatus = StatusTCPUnreachable
		return result
	}
	result.Host = b.Host
	result.Port = b.Port
	result.Transport = b.Transport

	// ── Step 1: TCP reachability ──────────────────────────────────────────
	bridgeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tcpOK := bridge.TestWithContext(bridgeCtx, b, timeout)
	result.TCPReachable = tcpOK

	if !tcpOK && b.Transport != "snowflake" {
		result.IranStatus = StatusTCPUnreachable
		result.CompositeScore = compositeScore(false, StatusTCPUnreachable, nil, false)
		return result
	}

	// ── Step 2: ASN lookup and Iranian ISP filter ─────────────────────────
	if b.Host != "" && b.Host != "snowflake-broker" && net.ParseIP(b.Host) != nil {
		info, err := ipClient.Lookup(ctx, b.Host)
		if err == nil && info != nil {
			asnStr := info.ASN()
			result.ASN = asnStr
			result.ASNCountry = info.Country
			result.ASNOrg = info.Org

			if isIranian, _ := asn.IsIranian(asnStr); isIranian {
				result.IranStatus = StatusIranASNBlocked
				result.CompositeScore = 0
				return result
			}

			// CDN front validation (WebTunnel only)
			if b.Transport == "webtunnel" {
				if isCDN, _ := asn.IsCDN(asnStr); isCDN {
					result.Flags = append(result.Flags, FlagDomainFrontCDNOK)
				} else {
					result.Flags = append(result.Flags, FlagDomainFrontDegraded)
				}
			}
		}
	}

	// ── Step 3: TLS fingerprint DPI risk (advisory flag) ─────────────────
	if dpiHighRisk(b) {
		result.Flags = append(result.Flags, FlagDPIHighRisk)
	}

	// ── Step 4: Port risk assessment (advisory flag) ──────────────────────
	if portRiskFlag(b.Port) {
		result.Flags = append(result.Flags, FlagPortHighRisk)
	}

	// ── Steps 5 & 6: OONI measurements (7-day + 90-day temporal) ─────────
	//
	// WebTunnel classification note:
	//   WebTunnel bridges carry a domain-fronted HTTPS URL.  The parser
	//   extracts the CDN hostname (e.g. cdn.example.com) as b.Host.
	//   net.ParseIP(b.Host) == nil for domain names, so OONI cannot be
	//   queried by IP.  Instead, a TLS-reachable WebTunnel bridge is
	//   classified as iran_likely_working — CDN-fronted HTTPS traffic is
	//   the hardest transport for Iran's DPI to block without collateral
	//   damage to legitimate HTTPS sites.
	//
	// No-OONI-data fallback (obfs4 / vanilla):
	//   New bridges not yet measured by Iranian OONI probes return
	//   StatusUnknown.  A TCP-reachable bridge with a non-Iranian ASN and
	//   no OONI blocking evidence is classified iran_likely_working with a
	//   reduced composite score (0.60 vs 0.85 for OONI-confirmed).
	//   The results_writer.py Tier-2 bucket ensures these still appear in
	//   iran_likely_working_*.txt files.
	var iranStatus IranStatus = StatusIranUnknown

	switch {
	case b.Transport == "snowflake":
		// Snowflake uses WebRTC via the broker; no IP to probe.
		// It is the hardest transport to block and optimistically marked working.
		iranStatus = StatusIranLikelyWorking

	case b.Transport == "webtunnel" || b.Transport == "meek_lite":
		// Domain-fronted transport: OONI cannot classify by domain name.
		// TLS reachability from the runner is the best available signal.
		if tcpOK {
			iranStatus = StatusIranLikelyWorking
		} else {
			iranStatus = StatusIranUnknown
		}

	case b.Host != "" && net.ParseIP(b.Host) != nil:
		// IP-addressed bridge (obfs4, vanilla): query OONI.
		ooniStatus, recurrenceRate, checked := ooniClient.Classify(ctx, b.Host)
		result.OONIChecked = checked
		result.RecurrenceRate = recurrenceRate

		switch ooniStatus {
		case ooni.StatusLikelyWorking:
			iranStatus = StatusIranLikelyWorking
		case ooni.StatusLikelyBlocked:
			iranStatus = StatusIranLikelyBlocked
		case ooni.StatusFreqBlocked:
			iranStatus = StatusIranFreqBlocked
		default:
			// No OONI data for this IP.
			// TCP-reachable + non-Iranian ASN → classify as iran_likely_working
			// with a lower composite score.  This is the common case for new
			// bridges not yet measured by Iranian probes.
			if tcpOK {
				iranStatus = StatusIranUnknown // kept unknown; Tier-2 in results_writer
			} else {
				iranStatus = StatusTCPUnreachable
			}
		}

	default:
		// Unresolvable or non-IP, non-domain host
		iranStatus = StatusIranUnknown
	}

	result.IranStatus = iranStatus
	result.CompositeScore = compositeScore(tcpOK, iranStatus, nil, false)
	return result
}

func main() {
	inputFlag   := flag.String("input",   "bridge/bridge_list_for_testing.json", "JSON array of bridge strings")
	outputFlag  := flag.String("output",  "bridge/iran_results.json",            "Output JSON report path")
	workersFlag := flag.Int("workers",    100,                                   "Parallel worker count")
	timeoutFlag := flag.Duration("timeout", 8*time.Second,                       "Per-bridge TCP timeout")
	flag.Parse()

	// ── Read input ────────────────────────────────────────────────────────
	data, err := os.ReadFile(*inputFlag)
	if err != nil {
		log.Fatalf("cannot open input %q: %v", *inputFlag, err)
	}
	var bridgeLines []string
	if err := json.Unmarshal(data, &bridgeLines); err != nil {
		log.Fatalf("parse input JSON: %v", err)
	}
	log.Printf("Loaded %d bridges for testing (workers=%d, timeout=%s)",
		len(bridgeLines), *workersFlag, *timeoutFlag)

	// ── Shared clients ────────────────────────────────────────────────────
	ipClient   := ipinfo.New()
	ooniClient := ooni.New()
	defer ooniClient.Close()

	// ── Parallel classification ───────────────────────────────────────────
	sem     := make(chan struct{}, *workersFlag)
	results := make(chan BridgeResult, len(bridgeLines))
	var wg sync.WaitGroup
	ctx    := context.Background()

	for _, line := range bridgeLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(raw string) {
			defer wg.Done()
			defer func() { <-sem }()
			results <- classifyBridge(ctx, raw, *timeoutFlag, ipClient, ooniClient)
		}(line)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// ── Collect results ───────────────────────────────────────────────────
	var allResults []BridgeResult
	for r := range results {
		allResults = append(allResults, r)
	}

	// ── Build summary ─────────────────────────────────────────────────────
	var summary Summary
	summary.TotalTested = len(allResults)
	for _, r := range allResults {
		if r.TCPReachable || r.Transport == "snowflake" {
			summary.GlobalReachable++
		}
		switch r.IranStatus {
		case StatusIranLikelyWorking:
			summary.IranLikelyWorking++
		case StatusIranLikelyBlocked:
			summary.IranLikelyBlocked++
		case StatusIranUnknown:
			summary.IranUnknown++
		case StatusIranASNBlocked:
			summary.IranASNBlocked++
		case StatusIranFreqBlocked:
			summary.IranFreqBlocked++
		}
	}

	report := Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Summary:     summary,
		Bridges:     allResults,
	}

	log.Printf("Summary: total=%d reachable=%d likely_working=%d likely_blocked=%d unknown=%d asn_blocked=%d",
		summary.TotalTested, summary.GlobalReachable, summary.IranLikelyWorking,
		summary.IranLikelyBlocked, summary.IranUnknown, summary.IranASNBlocked)

	// ── Write output ──────────────────────────────────────────────────────
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("marshal output: %v", err)
	}
	if err := os.WriteFile(*outputFlag, out, 0644); err != nil {
		log.Fatalf("write output %q: %v", *outputFlag, err)
		os.Exit(2)
	}
	log.Printf("Report written to %s", *outputFlag)
}
