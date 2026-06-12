// Package bridge provides canonical bridge-line parsing and low-level
// reachability testing shared by all Go binaries in TorShield-IR.
package bridge

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Bridge holds the parsed representation of a single Tor bridge line.
type Bridge struct {
	RawLine   string
	Host      string // IPv4, IPv6 address, or domain name
	Port      int
	Transport string // obfs4 | webtunnel | snowflake | meek_lite | vanilla
}

var (
	ip4PortRe  = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})`)
	ip6PortRe  = regexp.MustCompile(`\[([0-9a-fA-F:]{2,39})\]:(\d{1,5})`)
	httpsRe    = regexp.MustCompile(`(?i)https?://([^/:\s]+)(?::(\d+))?`)
)

// DetectTransport returns the transport name found in a bridge line.
func DetectTransport(line string) string {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "snowflake"):
		return "snowflake"
	case strings.Contains(l, "webtunnel"), strings.Contains(l, "url=https"):
		return "webtunnel"
	case strings.Contains(l, "obfs4"):
		return "obfs4"
	case strings.Contains(l, "meek"):
		return "meek_lite"
	default:
		return "vanilla"
	}
}

// Parse extracts the host, port, and transport from a raw bridge line.
// Returns an error only if no endpoint can be extracted at all.
func Parse(line string) (*Bridge, error) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "Bridge ") {
		line = line[7:]
	}
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, fmt.Errorf("empty or comment line")
	}

	transport := DetectTransport(line)

	// Snowflake uses WebRTC; there is no IP:port to extract from the bridge line
	// itself — connectivity is established through the snowflake broker URL.
	if transport == "snowflake" {
		return &Bridge{RawLine: line, Host: "snowflake-broker", Port: 0, Transport: "snowflake"}, nil
	}

	// WebTunnel and meek: prefer the HTTPS domain from the url= parameter.
	if transport == "webtunnel" || transport == "meek_lite" {
		if m := httpsRe.FindStringSubmatch(line); m != nil {
			port := 443
			if m[2] != "" {
				if p, err := strconv.Atoi(m[2]); err == nil {
					port = p
				}
			}
			return &Bridge{RawLine: line, Host: m[1], Port: port, Transport: transport}, nil
		}
	}

	// IPv6 [addr]:port
	if m := ip6PortRe.FindStringSubmatch(line); m != nil {
		port, _ := strconv.Atoi(m[2])
		return &Bridge{RawLine: line, Host: m[1], Port: port, Transport: transport}, nil
	}

	// IPv4 addr:port
	if m := ip4PortRe.FindStringSubmatch(line); m != nil {
		port, _ := strconv.Atoi(m[2])
		return &Bridge{RawLine: line, Host: m[1], Port: port, Transport: transport}, nil
	}

	return nil, fmt.Errorf("no parseable endpoint in: %q", line)
}
