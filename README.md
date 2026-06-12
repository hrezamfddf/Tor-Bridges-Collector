# 🌐 Tor Bridges Ultra Collector

> Auto-collected, tested, and Iran-scored Tor bridges.  
> GitHub Actions runs every hour — fresh bridges always available.  
> **Last update:** `2026-06-11 14:09 UTC`

## ⚠️ Notes for Iran Users

- **Internet cut (شبکه ملی):** Use `export/iran_cut_pack.txt` — contains Snowflake and WebTunnel bridges that survive NIN.
- **Normal censorship:** Use `export/iran_pack.txt` — top-ranked obfs4/WebTunnel bridges for Iran's DPI.
- **Port 443 bridges** are prioritised — Iran almost never blocks HTTPS.
- **IPv4 is more stable** than IPv6 inside Iran.

## ✅ Tested & Active (Recommended)

| Transport | IPv4 Tested | Count |
| :--- | :--- | :--- |
| **obfs4** | [obfs4_tested.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/obfs4_tested.txt) | **9** |
| **WebTunnel** | [webtunnel_tested.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/webtunnel_tested.txt) | **2** |
| **Snowflake** | [snowflake_tested.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/snowflake_tested.txt) | **8** |
| **Vanilla** | [vanilla_tested.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/vanilla_tested.txt) | **2** |
| **meek-lite** | [meek_lite_tested.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/meek_lite_tested.txt) | **2** |

## 🕐 Fresh Bridges (Last 72h)

| Transport | IPv4 | Count | IPv6 | Count |
| :--- | :--- | :--- | :--- | :--- |
| **obfs4** | [obfs4_72h.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/obfs4_72h.txt) | **16** | [obfs4_72h_ipv6.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/obfs4_72h_ipv6.txt) | **2** |
| **WebTunnel** | [webtunnel_72h.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/webtunnel_72h.txt) | **2** | [webtunnel_72h_ipv6.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/webtunnel_72h_ipv6.txt) | **0** |
| **Vanilla** | [vanilla_72h.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/vanilla_72h.txt) | **2** | [vanilla_72h_ipv6.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/vanilla_72h_ipv6.txt) | **0** |

## 📦 Full Archive

| Transport | IPv4 | Count | IPv6 | Count |
| :--- | :--- | :--- | :--- | :--- |
| **obfs4** | [obfs4.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/obfs4.txt) | **16** | [obfs4_ipv6.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/obfs4_ipv6.txt) | **2** |
| **WebTunnel** | [webtunnel.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/webtunnel.txt) | **2** | [webtunnel_ipv6.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/webtunnel_ipv6.txt) | **0** |
| **Snowflake** | [snowflake.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/snowflake.txt) | **8** | — | — |
| **Vanilla** | [vanilla.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/vanilla.txt) | **2** | [vanilla_ipv6.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/vanilla_ipv6.txt) | **0** |
| **meek-lite** | [meek_lite.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/bridge/meek_lite.txt) | **3** | — | — |

## 🇮🇷 Iran Optimised Packs

| Pack | Description |
| :--- | :--- |
| [iran_pack.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/export/iran_pack.txt) | Top 100 bridges ranked by Iran effectiveness score |
| [iran_cut_pack.txt](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/export/iran_cut_pack.txt) | Bridges for internet cut / شبکه ملی scenarios |
| [bridges_api.json](https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main/export/bridges_api.json) | Machine-readable JSON API |

## 📡 Transport Guide for Iran

| Transport | Anti-DPI | Works during cut | Speed | Recommended |
| :--- | :--- | :--- | :--- | :--- |
| Snowflake | ⭐⭐⭐⭐⭐ | ✅ | Medium | **Yes** |
| WebTunnel | ⭐⭐⭐⭐⭐ | ✅ (CDN) | Fast | **Yes** |
| obfs4 | ⭐⭐⭐⭐ | ❌ | Fast | **Yes** |
| meek-lite | ⭐⭐⭐⭐ | ✅ (Azure) | Slow | Fallback |
| Vanilla | ⭐ | ❌ | Fast | No |

## Disclaimer

For educational and archival purposes. Use bridges responsibly.

## 🔬 Advanced Anti-Filtering Features (NEW)

### AI-Powered Anti-DPI Engine (`--anti-dpi`)
Detects and counters Iran's DPI systems (Arvan DPI, SIAM, Kowsar, NGFW) with:
- Real-time threat analysis and risk scoring
- TLS fingerprint randomization (JA3 evasion)
- SNI evasion strategies (domain fronting, ECH encryption, padding)
- Traffic shaping recommendations (iat-mode=2, burst obfuscation, flow morphing)
- Entropy analysis for statistical fingerprinting detection

### Smart Anti-Filtering Engine (`--anti-filter`)
Comprehensive censorship circumvention system for Iran:
- Real-time censorship level monitoring (Level 1-5)
- ISP-specific blocking predictions (MCI, IRANCELL, Rightel, Shatel, Asiatech)
- Smart bridge selection optimized for current censorship state
- Automatic transport switching when DPI patterns change
- Temporal blocking pattern analysis (best connection windows)
- CDN front selection for NIN scenarios
- Bridge rotation scheduling to avoid fingerprinting

### Auto-Debug System (`--auto-debug`)
Fully autonomous debugging and self-healing:
- Python syntax error detection and auto-fix
- YAML workflow validation and repair
- Import dependency checking
- AI Gateway connectivity verification with LocalAIEngine fallback
- Bridge pipeline health monitoring
- Configuration integrity checks
- Automatic directory structure repair

### LocalAIEngine Fallback
When all external AI providers (Cerebras, Portkey, Cloudflare) are unavailable:
- Zero-dependency rule-based scoring engine activates automatically
- Iran-specific DPI knowledge base (Arvan, SIAM, Kowsar, NGFW, NIN)
- ISP-specific blocking predictions
- Censorship level detection (Level 1-5)
- Transport stack recommendations
- Bridge scoring and ranking
- The gateway **never fails** — always returns a valid response
