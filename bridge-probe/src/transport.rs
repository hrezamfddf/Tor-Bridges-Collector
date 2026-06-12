//! transport.rs — Transport-type detection and endpoint extraction.
//! TorShield-IR v2.0 — Extended transport support for Iran DPI evasion.

use anyhow::{anyhow, Result};
use regex::Regex;
use std::sync::OnceLock;

/// Supported pluggable transport types.
/// Extended for Iran-specific DPI-resistant transports.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Obfs4,
    WebTunnel,
    Snowflake,
    MeekLite,
    /// ShadowTLS v3 — TLS-masqueraded stream (high DPI resistance)
    ShadowTls,
    /// VLESS + XTLS-Reality — mirrors real TLS handshake of target domain
    VlessReality,
    /// Hysteria2 — QUIC/UDP transport with MASQ obfuscation
    Hysteria2,
    /// TUIC v5 — 0-RTT QUIC transport with UUID auth
    Tuic,
    Vanilla,
    Unknown,
}

/// DPI resistance tier (Iran SIAM scoring).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DpiTier {
    Maximum,   // Snowflake, Hysteria2 — Iran cannot block without collateral
    VeryHigh,  // WebTunnel, REALITY, ShadowTLS
    High,      // obfs4, TUIC
    Medium,    // meek_lite
    Low,       // Vanilla
}

impl Transport {
    /// Iran DPI resistance tier for scoring.
    pub fn dpi_tier(&self) -> DpiTier {
        match self {
            Transport::Snowflake    => DpiTier::Maximum,
            Transport::Hysteria2    => DpiTier::Maximum,
            Transport::WebTunnel    => DpiTier::VeryHigh,
            Transport::VlessReality => DpiTier::VeryHigh,
            Transport::ShadowTls    => DpiTier::VeryHigh,
            Transport::Obfs4        => DpiTier::High,
            Transport::Tuic         => DpiTier::High,
            Transport::MeekLite     => DpiTier::Medium,
            Transport::Vanilla      => DpiTier::Low,
            Transport::Unknown      => DpiTier::Low,
        }
    }

    /// Whether this transport can survive Iran NIN (internet cut).
    pub fn survives_nin(&self) -> bool {
        matches!(
            self,
            Transport::Snowflake    |
            Transport::WebTunnel    |
            Transport::MeekLite     |
            Transport::VlessReality |
            Transport::ShadowTls
        )
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Obfs4        => write!(f, "obfs4"),
            Transport::WebTunnel    => write!(f, "webtunnel"),
            Transport::Snowflake    => write!(f, "snowflake"),
            Transport::MeekLite     => write!(f, "meek_lite"),
            Transport::ShadowTls    => write!(f, "shadow_tls"),
            Transport::VlessReality => write!(f, "vless_reality"),
            Transport::Hysteria2    => write!(f, "hysteria2"),
            Transport::Tuic         => write!(f, "tuic"),
            Transport::Vanilla      => write!(f, "vanilla"),
            Transport::Unknown      => write!(f, "unknown"),
        }
    }
}

/// A parsed bridge endpoint.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub host:         String,
    pub port:         u16,
    pub transport:    Transport,
    pub raw:          String,
    pub uses_udp:     bool,   // true for QUIC-based transports
    pub sni:          Option<String>,  // extracted SNI for TLS probes
}

// Static regex compilation — compiled once, reused forever.
static IP4_PORT:    OnceLock<Regex> = OnceLock::new();
static IP6_PORT:    OnceLock<Regex> = OnceLock::new();
static HTTPS_URL:   OnceLock<Regex> = OnceLock::new();
static URI_HOSTPORT: OnceLock<Regex> = OnceLock::new();

fn ip4_re() -> &'static Regex {
    IP4_PORT.get_or_init(|| {
        Regex::new(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})").unwrap()
    })
}

fn ip6_re() -> &'static Regex {
    IP6_PORT.get_or_init(|| {
        Regex::new(r"\[([0-9a-fA-F:]{2,39})\]:(\d{1,5})").unwrap()
    })
}

fn https_re() -> &'static Regex {
    HTTPS_URL.get_or_init(|| {
        Regex::new(r"(?i)https?://([^/:\s]+)(?::(\d+))?").unwrap()
    })
}

fn uri_host_re() -> &'static Regex {
    URI_HOSTPORT.get_or_init(|| {
        // Matches hysteria2://user@host:port or tuic://uuid@host:port
        Regex::new(r"://(?:[^@/]+@)?([^/:]+):(\d+)").unwrap()
    })
}

/// Detect the transport type from a raw bridge line.
pub fn detect_transport(line: &str) -> Transport {
    let lower = line.to_lowercase();
    // QUIC-based (checked first — highest priority in Iran)
    if lower.starts_with("hysteria2://")                              { return Transport::Hysteria2; }
    if lower.starts_with("tuic://")                                   { return Transport::Tuic; }
    // TLS-camouflage
    if lower.contains("shadow-tls") || lower.contains("shadowtls")   { return Transport::ShadowTls; }
    if lower.contains("xtls-rprx-reality") || lower.contains("security=reality") {
        return Transport::VlessReality;
    }
    // Standard Tor PTs
    if lower.contains("snowflake")                                    { return Transport::Snowflake; }
    if lower.contains("webtunnel") || lower.contains("url=https")    { return Transport::WebTunnel; }
    if lower.contains("obfs4")                                        { return Transport::Obfs4; }
    if lower.contains("meek")                                         { return Transport::MeekLite; }
    Transport::Vanilla
}

/// Extract SNI hint from a bridge line (for TLS probe camouflage scoring).
pub fn extract_sni(line: &str) -> Option<String> {
    // VLESS-Reality: sni=example.com
    if let Some(pos) = line.find("sni=") {
        let rest = &line[pos + 4..];
        let end = rest.find(|c: char| c == '&' || c == ' ' || c == '\n').unwrap_or(rest.len());
        let sni = rest[..end].trim().to_string();
        if !sni.is_empty() { return Some(sni); }
    }
    // WebTunnel: url=https://example.com/path
    if let Some(caps) = https_re().captures(line) {
        return Some(caps[1].to_string());
    }
    None
}

/// Parse a raw bridge line into an Endpoint.
pub fn parse_endpoint(raw: &str) -> Result<Endpoint> {
    let line = raw.trim().strip_prefix("Bridge ").unwrap_or(raw.trim());
    if line.is_empty() || line.starts_with('#') {
        return Err(anyhow!("empty or comment line"));
    }

    let transport = detect_transport(line);
    let sni       = extract_sni(line);
    let uses_udp  = matches!(transport, Transport::Hysteria2 | Transport::Tuic);

    // Snowflake — broker handles routing, no direct IP needed.
    if transport == Transport::Snowflake {
        return Ok(Endpoint {
            host:      "snowflake-broker.torproject.net".into(),
            port:      443,
            transport: Transport::Snowflake,
            raw:       raw.to_string(),
            uses_udp:  false,
            sni:       Some("snowflake-broker.torproject.net".into()),
        });
    }

    // URI-scheme protocols (hysteria2://, tuic://)
    if matches!(transport, Transport::Hysteria2 | Transport::Tuic) {
        if let Some(caps) = uri_host_re().captures(line) {
            let host = caps[1].to_string();
            let port: u16 = caps[2].parse().unwrap_or(443);
            return Ok(Endpoint { host, port, transport, raw: raw.to_string(), uses_udp, sni });
        }
    }

    // WebTunnel / meek / REALITY: prefer HTTPS URL host.
    if matches!(transport, Transport::WebTunnel | Transport::MeekLite | Transport::VlessReality) {
        if let Some(caps) = https_re().captures(line) {
            let host = caps[1].to_string();
            let port: u16 = caps.get(2)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(443);
            return Ok(Endpoint { host, port, transport, raw: raw.to_string(), uses_udp, sni });
        }
    }

    // IPv6 [addr]:port
    if let Some(caps) = ip6_re().captures(line) {
        let host = caps[1].to_string();
        let port: u16 = caps[2].parse().unwrap_or(0);
        return Ok(Endpoint { host, port, transport, raw: raw.to_string(), uses_udp, sni });
    }

    // IPv4 addr:port
    if let Some(caps) = ip4_re().captures(line) {
        let host = caps[1].to_string();
        let port: u16 = caps[2].parse().unwrap_or(0);
        return Ok(Endpoint { host, port, transport, raw: raw.to_string(), uses_udp, sni });
    }

    Err(anyhow!("no parseable endpoint in: {:?}", line))
}
