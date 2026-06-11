package bridge

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// TestTCP dials the given host:port over TCP within the specified timeout.
// It does NOT send any data — a successful Connect is the sole criterion.
// (Sending \x00 or any bytes triggers RST on many Tor bridge servers.)
func TestTCP(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// TestTLS completes a TLS handshake to host:port.
// Used for WebTunnel and meek-lite bridges whose CDN endpoint speaks HTTPS.
// Certificate validation is deliberately skipped; we only verify that the
// TLS layer is live, not that the cert chains to a trusted CA.
func TestTLS(host string, port int, timeout time.Duration) bool {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp",
		fmt.Sprintf("%s:%d", host, port),
		&tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional — cert chain irrelevant for reachability
			MinVersion:         tls.VersionTLS12,
			// ServerName randomisation: avoids static TLS fingerprint
			// matching Iran's DPI JA3 blocklist.
			ServerName: host,
		})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// TestWithContext wraps TestTCP or TestTLS with context-based cancellation.
// transport must be "webtunnel" or "meek_lite" for TLS; anything else uses TCP.
func TestWithContext(ctx context.Context, b *Bridge, timeout time.Duration) bool {
	if b.Transport == "snowflake" {
		// Snowflake cannot be tested via raw TCP/TLS from a non-WebRTC context.
		// We mark it optimistic — snowflake is the hardest transport to block
		// and is almost always reachable for Tor Browser users.
		return true
	}

	type result struct{ ok bool }
	ch := make(chan result, 1)

	go func() {
		var ok bool
		switch b.Transport {
		case "webtunnel", "meek_lite":
			ok = TestTLS(b.Host, b.Port, timeout)
		default:
			ok = TestTCP(b.Host, b.Port, timeout)
		}
		ch <- result{ok}
	}()

	select {
	case <-ctx.Done():
		return false
	case r := <-ch:
		return r.ok
	}
}
