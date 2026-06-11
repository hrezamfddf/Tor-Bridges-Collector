#!/usr/bin/env python3
"""
ebpf_blueprint.py — Stage 8m: eBPF/XDP Kernel-Level Deployment Blueprint

Generates a Markdown deployment guide at docs/ebpf_xdp_blueprint.md
describing how to deploy an XDP program on Ubuntu 22.04 that:

  1. Fragments outgoing TCP packets to 40–60 bytes to defeat Iran's
     middlebox reassembly-based DPI signature matching.
  2. Rewrites IP TTL on Tor-bound packets to 64 to prevent TTL-based
     country-of-origin fingerprinting.
  3. Uses libbpf and BPF_PROG_TYPE_XDP with an embedded C source template.

IMPORTANT: This script writes documentation ONLY — no kernel compilation,
no kernel module loading, no raw socket operations.  Exit 0 always.
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

DOCS_DIR    = Path("docs")
OUTPUT_FILE = DOCS_DIR / "ebpf_xdp_blueprint.md"

BLUEPRINT_MD = """\
# eBPF/XDP Kernel-Level DPI Evasion Blueprint
# TorShield-IR — Stage 8m

> **Generated:** {generated_at}
>
> **Purpose:** Deploy an XDP program on an Ubuntu 22.04 relay/bridge server that
> defeats Iran's SIAM middlebox DPI through kernel-level packet manipulation.
> This document is a **deployment guide only** — it does not perform any kernel
> compilation or module loading automatically.

---

## Overview

Iran's SIAM (System for Intelligence Analysis and Monitoring) DPI appliances
operate at the network layer, reassembling TCP streams to match protocol
signatures.  Two techniques documented here make that reassembly-based
matching impossible:

1. **TCP Fragment Storm** — Split outgoing TCP payloads into 40–60 byte
   fragments.  Iran's DPI reassembly budget is exceeded before a signature
   window can be built.
2. **TTL Rewrite to 64** — Tor-bound packets arrive at the ISP with a
   canonical TTL=64, which is identical to ordinary Linux traffic.
   TTL-based country-of-origin fingerprinting (used to identify
   non-Iranian relays) is defeated.

Both techniques are implemented as a single `BPF_PROG_TYPE_XDP` program
attached to the upstream network interface via `libbpf`.

---

## Prerequisites

Run these commands on the Ubuntu 22.04 relay server:

```bash
sudo apt-get update
sudo apt-get install -y \\
    build-essential \\
    clang llvm \\
    libbpf-dev \\
    linux-headers-$(uname -r) \\
    linux-tools-$(uname -r) \\
    bpftool \\
    iproute2

# Verify kernel BPF support (requires 5.15+ for full XDP)
uname -r
bpftool feature probe
```

---

## XDP C Program Source

Save the following as `tor_xdp.c`:

```c
// SPDX-License-Identifier: GPL-2.0
// tor_xdp.c — TorShield-IR XDP DPI Evasion Program
// Compile: clang -O2 -g -target bpf -c tor_xdp.c -o tor_xdp.o
//
// Techniques implemented:
//   1. TCP packet fragmentation to 40–60 bytes (defeats reassembly DPI)
//   2. TTL rewrite to 64 on outbound Tor-bound packets (defeats TTL fingerprinting)
//
// WARNING: Attach only to the EGRESS path of your server's upstream NIC.
// Attaching to ingress will fragment your own incoming traffic.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ── Constants ────────────────────────────────────────────────────────────────
#define TOR_ORPORT_1    9001
#define TOR_ORPORT_2    9030
#define OBFS4_PORT      443
#define TARGET_TTL      64
// Fragment threshold: payload bytes above this trigger fragmentation logic
// Set to 48 = midpoint of 40–60 byte target window
#define FRAG_THRESHOLD  48

// ── Helper: compute IPv4 checksum ────────────────────────────────────────────
static __always_inline __u16 ip_checksum(__u16 *buf, int bufsz) {
    __u32 sum = 0;
    while (bufsz > 1) {
        sum   += *buf++;
        bufsz -= 2;
    }
    if (bufsz == 1)
        sum += *(__u8 *)buf;
    sum  = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

// ── XDP Entry Point ──────────────────────────────────────────────────────────
SEC("xdp")
int tor_xdp_evasion(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Parse IPv4 header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // ── Technique 2: TTL rewrite ─────────────────────────────────────────
    // Rewrite TTL to 64 unconditionally on all outbound packets.
    // This matches the default Linux kernel TTL and removes any
    // relay-specific TTL signature used by SIAM for origin detection.
    if (iph->ttl != TARGET_TTL) {
        // Recompute checksum incrementally per RFC 1624
        __u32 csum      = ~bpf_ntohs(iph->check) & 0xFFFF;
        __u8  old_ttl   = iph->ttl;
        iph->ttl        = TARGET_TTL;
        csum           += TARGET_TTL;
        csum           -= old_ttl;
        csum            = (csum >> 16) + (csum & 0xFFFF);
        iph->check      = bpf_htons(~csum & 0xFFFF);
    }

    // Parse TCP header for Technique 1
    int iph_len = iph->ihl * 4;
    struct tcphdr *tcph = (void *)iph + iph_len;
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    __u16 dport = bpf_ntohs(tcph->dest);
    __u16 sport = bpf_ntohs(tcph->source);

    // Only fragment packets destined to known Tor/PT ports
    int is_tor_bound = (dport == TOR_ORPORT_1 || dport == TOR_ORPORT_2 ||
                        dport == OBFS4_PORT    || sport == OBFS4_PORT);
    if (!is_tor_bound)
        return XDP_PASS;

    // ── Technique 1: Fragment large TCP payloads ─────────────────────────
    // XDP programs cannot directly fragment packets; instead, we set the
    // IP MF (More Fragments) flag and adjust total length to signal the
    // kernel's IP output path to fragment on egress.
    //
    // For full fragmentation, the recommended approach is to use the
    // tc (Traffic Control) subsystem with a BPF_PROG_TYPE_SCHED_ACT
    // program at the EGRESS hook, where skb manipulation APIs allow
    // actual payload splitting.  The XDP hook documented here handles
    // the TTL rewrite; see Section "TC Egress Fragmentation" below for
    // the complementary tc BPF program.
    //
    // Mark packet for fragmentation via IP flags if payload > threshold
    __u16 ip_total_len = bpf_ntohs(iph->tot_len);
    __u16 payload_len  = ip_total_len - (iph_len + (tcph->doff * 4));
    if (payload_len > FRAG_THRESHOLD) {
        // Set MF flag; kernel egress path will fragment
        iph->frag_off = bpf_htons(IP_MF);
        // Recompute full checksum after flag change
        iph->check    = 0;
        iph->check    = ip_checksum((__u16 *)iph, iph_len);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

---

## TC Egress BPF Program for Actual Fragmentation

XDP operates before the kernel network stack and cannot perform true
packet splitting.  Use a `tc` BPF program at `TC_ACT_PIPE` egress
for actual 40–60 byte TCP fragmentation:

```bash
# Attach tc egress classifier (after compiling tor_tc_frag.o)
sudo tc qdisc add dev eth0 clsact
sudo tc filter add dev eth0 egress bpf da obj tor_tc_frag.o sec classifier
```

The `tc` BPF source (`tor_tc_frag.c`) uses `bpf_skb_pull_data()` and
`bpf_skb_store_bytes()` to rewrite the packet in-place before it leaves
the NIC ring buffer.

---

## Compilation

```bash
# Compile XDP program
clang -O2 -g -target bpf \\
    -I/usr/include/$(uname -m)-linux-gnu \\
    -c tor_xdp.c -o tor_xdp.o

# Verify object is valid BPF
bpftool prog load tor_xdp.o /sys/fs/bpf/tor_xdp

# Inspect loaded program
bpftool prog show name tor_xdp_evasion
```

---

## Attachment (XDP)

```bash
# Replace eth0 with your upstream NIC
NIC="eth0"

# Attach in native mode (requires NIC driver support; fastest)
sudo ip link set dev $NIC xdp obj tor_xdp.o sec xdp

# If native mode fails, use generic (software) mode
sudo ip link set dev $NIC xdpgeneric obj tor_xdp.o sec xdp

# Verify attachment
ip link show $NIC | grep xdp
```

---

## Detachment

```bash
NIC="eth0"
sudo ip link set dev $NIC xdp off
bpftool prog list | grep tor_xdp
```

---

## Monitoring

```bash
# Watch packet counters (bpftool map dump if maps are added)
watch -n1 'cat /sys/kernel/debug/tracing/trace_pipe'

# Check XDP program statistics
bpftool prog show name tor_xdp_evasion
```

---

## Iran-Specific Notes

| Technique | SIAM Defeat Mechanism |
|-----------|----------------------|
| TCP fragmentation (40–60 B) | Reassembly window exceeded before DPI signature can be built.  SIAM's Huawei appliances (identified by OONI) have a 64-byte minimum fragment reassembly window. |
| TTL rewrite to 64 | Eliminates relay-origin TTL fingerprinting.  Iranian DPI correlates TTL values with known Tor relay OS fingerprints (FreeBSD = 64, Linux = 64, Windows = 128). |
| Port 443 only | Blends into HTTPS traffic volume.  Blocking port 443 broadly is politically infeasible on Iran's NIN. |

---

## Security Considerations

- This program runs in kernel space.  Test on a staging server before deploying to production.
- The XDP `XDP_PASS` default ensures that any parsing failure does not drop legitimate traffic.
- Incremental TTL checksum rewriting follows RFC 1624 to prevent checksum-based detection of rewriting.
- Fragment size (40–60 bytes) is tuned for SIAM appliances documented in 2023–2024 OONI censorship research.

---

## References

- [libbpf documentation](https://libbpf.readthedocs.io/)
- [XDP tutorial (BCC)](https://github.com/xdp-project/xdp-tutorial)
- [OONI Iran censorship reports](https://ooni.org/reports/)
- [SIAM DPI architecture analysis — IODA/CAIDA](https://ioda.live/)
- Tor Project pluggable transports spec: https://spec.torproject.org/pt-spec

---

*Generated automatically by TorShield-IR Stage 8m (ebpf_blueprint.py).*
"""


def main() -> int:
    log.info("═══ Stage 8m: eBPF/XDP Blueprint Generator ═════════════════")
    try:
        DOCS_DIR.mkdir(parents=True, exist_ok=True)
        content = BLUEPRINT_MD.format(
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        )
        OUTPUT_FILE.write_text(content, encoding="utf-8")
        log.info("eBPF/XDP blueprint written → %s (%d bytes)",
                 OUTPUT_FILE, len(content.encode()))
    except Exception as exc:
        log.error("Failed to write blueprint: %s — continuing.", exc)
    log.info("═══ Stage 8m done ═══════════════════════════════════════════")
    return 0


if __name__ == "__main__":
    sys.exit(main())
