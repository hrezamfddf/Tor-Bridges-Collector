#![deny(warnings)]
//! bridge-probe — TorShield-IR pluggable-transport handshake prober v2.0
//!
//! Reads a JSON array (or newline-delimited list) of bridge strings from stdin,
//! probes each concurrently via Tokio, and writes per-bridge JSON results
//! as a single pretty-printed array to stdout.
//!
//! Each result object includes:
//!   bridge         — original bridge line
//!   status         — reachable | timeout | refused | error | quic_reachable
//!   latency_ms     — measured round-trip time in milliseconds
//!   pt_type        — transport identifier (obfs4, snowflake, webtunnel, …)
//!   nin_survivable — true when this transport survives an Iran NIN internet cut
//!   dpi_tier       — Iran DPI-resistance tier (Maximum → Low)
//!   probe_layer    — protocol layer used: tcp | tls | udp | assumed
//!   probe_sni      — SNI hostname passed to TLS probe (null for TCP/UDP probes)
//!
//! Usage:
//!   cat bridge/bridges.json | ./bridge-probe
//!   cat bridge/bridges.json | ./bridge-probe --timeout 20 --workers 50
//!   cat bridge/bridges.json | ./bridge-probe --nin-only

use std::io::{self, Read};
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tokio::task::JoinSet;
use tracing::info;

mod probe;
mod transport;

use probe::{probe, ProbeStatus};
use transport::parse_endpoint;

/// TorShield-IR pluggable-transport bridge prober — Iran-optimised.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Per-bridge probe timeout in seconds.
    #[arg(long, default_value_t = 30)]
    timeout: u64,

    /// Maximum concurrent probe tasks.
    #[arg(long, default_value_t = 50)]
    workers: usize,

    /// Output only bridges that survive Iran NIN (internet cut) mode.
    #[arg(long, default_value_t = false)]
    nin_only: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bridge_probe=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    let probe_timeout = Duration::from_secs(args.timeout);

    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;

    // Accept both JSON array and bare newline-delimited bridge lines.
    let bridge_lines: Vec<String> = serde_json::from_str(&raw).unwrap_or_else(|_| {
        raw.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    });

    let total = bridge_lines.len();
    info!(
        "TorShield-IR bridge-probe v2.0 | bridges={} timeout={}s workers={} nin_only={}",
        total, args.timeout, args.workers, args.nin_only
    );

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(args.workers));
    let mut join_set: JoinSet<probe::ProbeResult> = JoinSet::new();

    for line in bridge_lines {
        let ep = match parse_endpoint(&line) {
            Ok(ep) => ep,
            Err(e) => {
                tracing::warn!("Skipping unparseable bridge {:?}: {}", line, e);
                continue;
            }
        };

        if args.nin_only && !ep.transport.survives_nin() {
            tracing::debug!("Skipping non-NIN-survivable transport: {}", ep.transport);
            continue;
        }

        let sem     = semaphore.clone();
        let timeout = probe_timeout;
        join_set.spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed");
            probe(&ep, timeout).await
        });
    }

    let mut results: Vec<probe::ProbeResult> = Vec::new();
    while let Some(res) = join_set.join_next().await {
        match res {
            Ok(r)  => results.push(r),
            Err(e) => tracing::error!("Probe task panicked: {}", e),
        }
    }

    // Summary statistics on stderr.
    let reachable = results.iter().filter(|r| {
        r.status == ProbeStatus::Reachable || r.status == ProbeStatus::QuicReachable
    }).count();
    let nin_ok = results.iter().filter(|r| r.nin_survivable).count();
    info!(
        "Complete | reachable={}/{} nin_survivable={}",
        reachable, results.len(), nin_ok
    );

    // Results on stdout as a JSON array.
    println!("{}", serde_json::to_string_pretty(&results)?);
    Ok(())
}
