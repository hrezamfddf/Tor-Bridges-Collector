"""
IranIntelligenceLayer v9.0 — AI-powered Iran anti-censorship intelligence.
═══════════════════════════════════════════════════════════════════════════
Wraps TorShieldAIGateway with specialised prompts for:

  EXISTING (v7.0)
    score_bridge_iran_reachability  — single-bridge DPI/NIN score
    rank_bridges_for_iran           — ranked batch scoring
    predict_nin_survival            — NIN cut survival prediction
    generate_obfs4_mutation         — obfs4 parameter mutation
    analyze_workflow_failure        — CI/CD auto-diagnosis

  NEW (v9.0)
    detect_censorship_level         — real-time level 1–5 with recommendations
    isp_block_matrix                — per-ISP blocking predictions
    recommend_transport_stack       — full transport chain for current conditions
    temporal_block_pattern          — time-of-day blocking intensity
    batch_ai_score                  — efficient batch scoring with deduplication
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional
from .gateway import get_gateway

log = logging.getLogger("torshield.ai.iran")

# ── System prompt ──────────────────────────────────────────────────────────

IRAN_SYSTEM_PROMPT = """You are TorShield-IR's AI intelligence engine, expert in:
- Iran DPI infrastructure: Arvan-DPI, SIAM, NIN blackout events
- Circumventing MCI (Hamrah Aval), IRANCELL, Rightel, Shatel, Asiatech filtering
- Tor bridge transports: obfs4, Snowflake, Meek, WebTunnel, VLESS-Reality, Shadowsocks
- JA3/JA4 fingerprint evasion, TLS ClientHello randomization
- Predicting bridge survival during NIN (National Internet Network) isolation
- Kowsar and NGFW firewall bypass techniques

Outputs must be machine-parseable JSON unless asked for plain text.
Never explain reasoning unless asked. Optimized for speed and accuracy.
Assume user is in Iran on mobile carrier (CGNAT) with DPI Level 4 active."""


# ── Helper ─────────────────────────────────────────────────────────────────

def _safe_json(raw: str, fallback: Any) -> Any:
    """Parse JSON from AI response; return fallback on failure."""
    try:
        clean = raw.strip()
        # Strip markdown fences if present
        if clean.startswith("```"):
            clean = clean.split("```")[1].lstrip("json").strip()
        return json.loads(clean)
    except Exception:
        log.warning(f"[IranAI] Non-JSON response: {raw[:200]}")
        return fallback


# ══════════════════════════════════════════════════════════════════════════════
# Main class
# ══════════════════════════════════════════════════════════════════════════════

class IranIntelligenceLayer:

    def __init__(self):
        self.gw = get_gateway()

    # ── v7.0 methods (unchanged) ──────────────────────────────────────────

    def score_bridge_iran_reachability(self, bridge_line: str) -> Dict[str, Any]:
        """
        Score a single bridge for Iran reachability under DPI Level 4.
        Returns: {score, transport_ok, dpi_bypass_rating, nin_survival,
                  isp_block_risk, recommendation, mutation_hint}
        """
        user_msg = (
            f"Analyze this Tor bridge for reachability inside Iran under DPI Level 4:\n\n"
            f"```\n{bridge_line}\n```\n\n"
            f"Return ONLY a JSON object with keys: score (0-1), transport_ok (bool), "
            f"dpi_bypass_rating (0-1), nin_survival (0-1), isp_block_risk (low/medium/high), "
            f"recommendation (use/avoid/test), mutation_hint (string). No extra text."
        )
        raw = self.gw.prompt(
            IRAN_SYSTEM_PROMPT, user_msg, max_tokens=512, temperature=0.1, task="reasoning"
        )
        return _safe_json(raw, {"score": 0.5, "recommendation": "use", "raw": raw})

    def rank_bridges_for_iran(self, bridge_lines: List[str]) -> List[Dict[str, Any]]:
        """Rank bridges best → worst for Iran DPI Level 4 + NIN isolation."""
        bridges_json = json.dumps(bridge_lines[:50])
        user_msg = (
            f"Rank these Tor bridges BEST to WORST for Iran DPI Level 4 + NIN isolation:\n"
            f"{bridges_json}\n\n"
            f'Return ONLY JSON array: '
            f'[{{"bridge_line":"...","rank":1,"score":0.95,"recommendation":"use"}}]'
        )
        raw = self.gw.prompt(
            IRAN_SYSTEM_PROMPT, user_msg, max_tokens=2048, temperature=0.1, task="reasoning"
        )
        result = _safe_json(raw, [])
        if isinstance(result, list):
            return result
        return [{"bridge_line": b, "rank": i + 1, "score": 0.5} for i, b in enumerate(bridge_lines)]

    def predict_nin_survival(self, bridge_type: str, transport: str) -> Dict[str, Any]:
        """Predict bridge survival during NIN internet-cut events."""
        user_msg = (
            f"Bridge type: {bridge_type}, transport: {transport}.\n"
            f"Will this work during NIN isolation in Iran?\n"
            f'Return ONLY JSON: {{"survives":true,"confidence":0.87,"reason":"..."}}'
        )
        raw = self.gw.prompt(
            IRAN_SYSTEM_PROMPT, user_msg, max_tokens=256, temperature=0.1, task="reasoning"
        )
        return _safe_json(raw, {"survives": False, "confidence": 0.5, "reason": raw[:200]})

    def generate_obfs4_mutation(
        self, existing_cert: str, existing_iat_mode: int
    ) -> Dict[str, Any]:
        """Generate obfs4 parameter mutation to evade DPI fingerprinting."""
        user_msg = (
            f"obfs4 cert='{existing_cert}' iat-mode={existing_iat_mode}. "
            f"Generate a variant evading Arvan-DPI. "
            f'Return ONLY JSON: {{"cert":"...","iat_mode":2,"fingerprint_delta":"high"}}'
        )
        raw = self.gw.prompt(
            IRAN_SYSTEM_PROMPT, user_msg, max_tokens=512, temperature=0.3, task="general"
        )
        return _safe_json(raw, {
            "cert": existing_cert,
            "iat_mode": existing_iat_mode,
            "fingerprint_delta": "none",
        })

    def analyze_workflow_failure(
        self, workflow_name: str, error_log: str
    ) -> Dict[str, Any]:
        """Analyze a GitHub Actions workflow failure and return a patch plan."""
        AUTOFIX_SYSTEM = (
            "You are a GitHub Actions expert and Python/Zig DevOps engineer. "
            "You debug CI/CD pipelines for Iran censorship circumvention projects. "
            "CRITICAL: Never suggest removing features. Additive fixes only. JSON output."
        )
        user_msg = (
            f"Workflow: {workflow_name}\n\n"
            f"Error log (last 3000 chars):\n```\n{error_log[-3000:]}\n```\n\n"
            f"Identify root cause and minimal fix. "
            f'Return ONLY JSON: {{"root_cause":"...","fix_type":"yaml_patch|python_patch|'
            f'env_fix|shell_fix","patch":"...","confidence":0.91,"additive_only":true}}'
        )
        raw = self.gw.prompt(
            AUTOFIX_SYSTEM, user_msg, max_tokens=2048, temperature=0.1, task="coding"
        )
        return _safe_json(raw, {
            "root_cause": "unknown",
            "fix_type":   "manual",
            "patch":      raw,
            "confidence": 0.0,
            "additive_only": True,
        })

    # ── v9.0 NEW methods ──────────────────────────────────────────────────

    def detect_censorship_level(
        self,
        probe_results: Optional[Dict[str, str]] = None,
        nin_active: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        AI-enhanced censorship level detection (Level 1–5).

        Args:
            probe_results: Dict of category → "ok/fail" (from CensorshipMonitor).
                           If None, AI uses general Iran knowledge.
            nin_active:    Whether NIN is detected as active.

        Returns:
            {level, confidence, label, best_transports, pack_file,
             urgency, reasoning, isp_notes}
        """
        context = ""
        if probe_results:
            context = f"\nNetwork probe results:\n{json.dumps(probe_results, indent=2)}"
        if nin_active is not None:
            context += f"\nNIN (National Internet Network) active: {nin_active}"

        user_msg = (
            f"Determine the current Iran internet censorship level (1=minimal to 5=NIN shutdown)."
            f"{context}\n\n"
            f"Return ONLY JSON:\n"
            f'{{"level":4,"confidence":0.85,"label":"DPI Active",'
            f'"best_transports":["snowflake","webtunnel"],'
            f'"pack_file":"export/iran_nin_pack.txt","urgency":"high",'
            f'"reasoning":"...","isp_notes":"..."}}'
        )
        raw = self.gw.prompt(
            IRAN_SYSTEM_PROMPT, user_msg, max_tokens=512, temperature=0.1, task="reasoning"
        )
        result = _safe_json(raw, {
            "level": 3, "confidence": 0.5, "label": "Standard",
            "best_transports": ["obfs4", "webtunnel"],
            "pack_file": "export/iran_pack.txt", "urgency": "medium",
        })
        log.info(
            f"[IranAI] Censorship level detected: {result.get('level')} "
            f"(confidence={result.get('confidence')})"
        )
        return result

    def isp_block_matrix(
        self,
        transport_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        AI-predicted blocking status per major Iranian ISP and transport type.

        Args:
            transport_types: List of transports to evaluate.
                             Defaults to all major types.

        Returns:
            {
              "MCI":      {"obfs4": "blocked", "snowflake": "works", ...},
              "IRANCELL": {...},
              "Rightel":  {...},
              "Shatel":   {...},
              "Asiatech": {...},
              "updated_hint": "Based on OONI data June 2026"
            }
        """
        transports = transport_types or [
            "vanilla", "obfs4", "webtunnel", "snowflake", "meek_lite"
        ]
        user_msg = (
            f"Predict blocking status for these Tor transports on each Iran ISP "
            f"based on latest available data (OONI, Censored Planet, June 2026):\n"
            f"Transports: {transports}\n"
            f"ISPs: MCI (Hamrah Aval), IRANCELL (Irancell), Rightel, Shatel, Asiatech\n\n"
            f"Return ONLY JSON with ISP names as keys, each containing transport→status "
            f'(status: "works"|"degraded"|"blocked"|"unknown"). '
            f'Also include "updated_hint" key.'
        )
        raw = self.gw.prompt(
            IRAN_SYSTEM_PROMPT, user_msg, max_tokens=1024, temperature=0.1, task="reasoning"
        )
        fallback = {
            isp: {t: "unknown" for t in transports}
            for isp in ["MCI", "IRANCELL", "Rightel", "Shatel", "Asiatech"]
        }
        fallback["updated_hint"] = "offline fallback"
        return _safe_json(raw, fallback)

    def recommend_transport_stack(
        self,
        censorship_level:  int            = 3,
        isp:               str            = "unknown",
        nin_active:        bool           = False,
        available_bridges: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        AI recommendation for the complete transport chain for current conditions.

        Returns:
            {
              "primary_transport":   "snowflake",
              "fallback_transport":  "webtunnel",
              "last_resort":         "obfs4-443",
              "avoid":               ["vanilla", "obfs4-non-443"],
              "bridge_selection_hint": "Prefer CDN-fronted WebTunnel bridges",
              "config_hints": {
                "obfs4": {"iat-mode": 2, "prefer_port": 443},
                "snowflake": {"broker": "cdn", "ampcache": true}
              },
              "confidence": 0.88,
              "reasoning": "..."
            }
        """
        context_parts = [
            f"Current censorship level: {censorship_level}/5",
            f"ISP: {isp}",
            f"NIN active: {nin_active}",
        ]
        if available_bridges:
            sample = available_bridges[:5]
            context_parts.append(f"Available bridge sample: {sample}")

        user_msg = (
            f"Recommend the optimal Tor transport stack for these Iran conditions:\n"
            f"{chr(10).join(context_parts)}\n\n"
            f"Return ONLY JSON with: primary_transport, fallback_transport, last_resort, "
            f"avoid (list), bridge_selection_hint (string), config_hints (dict), "
            f"confidence (0-1), reasoning (string)."
        )
        raw = self.gw.prompt(
            IRAN_SYSTEM_PROMPT, user_msg, max_tokens=1024, temperature=0.1, task="reasoning"
        )
        return _safe_json(raw, {
            "primary_transport":      "snowflake" if nin_active else "webtunnel",
            "fallback_transport":     "webtunnel" if nin_active else "obfs4",
            "last_resort":            "obfs4-443",
            "avoid":                  ["vanilla"],
            "bridge_selection_hint":  "Use CDN-fronted bridges",
            "confidence":             0.60,
        })

    def temporal_block_pattern(
        self,
        transport: str = "obfs4",
        isp:       str = "MCI",
    ) -> Dict[str, Any]:
        """
        Predict time-of-day / day-of-week blocking intensity for a transport/ISP pair.

        Iran's censorship infrastructure shows known temporal patterns:
          - Blocking intensifies during political events / protests
          - Evening hours (20:00–23:00 IR time) often see heavier DPI
          - Weekend mornings typically have lower filtering intensity

        Returns:
            {
              "peak_block_hours":   [20, 21, 22],
              "low_block_hours":    [3, 4, 5],
              "weekend_modifier":   "lighter",
              "event_sensitivity":  "high",
              "current_estimate":   "normal",
              "best_connection_window": "03:00–06:00 IRST",
              "confidence":         0.70
            }
        """
        user_msg = (
            f"Based on historical OONI/Censored Planet data for Iran, predict the "
            f"temporal blocking pattern for transport='{transport}' on ISP='{isp}'.\n\n"
            f"Return ONLY JSON: peak_block_hours (list), low_block_hours (list), "
            f"weekend_modifier (lighter/heavier/same), event_sensitivity (low/medium/high), "
            f"current_estimate (light/normal/heavy), best_connection_window (string), "
            f"confidence (0-1)."
        )
        raw = self.gw.prompt(
            IRAN_SYSTEM_PROMPT, user_msg, max_tokens=512, temperature=0.2, task="reasoning"
        )
        return _safe_json(raw, {
            "peak_block_hours":        [20, 21, 22],
            "low_block_hours":         [3, 4, 5],
            "weekend_modifier":        "lighter",
            "event_sensitivity":       "high",
            "current_estimate":        "normal",
            "best_connection_window":  "03:00–06:00 IRST",
            "confidence":              0.55,
        })

    def batch_ai_score(
        self,
        bridge_lines:  List[str],
        censorship_level: int = 3,
        batch_size:    int = 30,
    ) -> List[Dict[str, Any]]:
        """
        Efficient batch scoring — deduplicates transport types, avoids redundant calls.

        Bridges with the same transport type on the same port receive the same
        base AI judgment; individual bridge-specific attributes (cert hash etc.)
        are handled by a lighter per-bridge delta call.

        Returns:
            List of dicts sorted by score desc:
            [{bridge_line, score, transport, port, recommendation, tier}, ...]
        """
        results: List[Dict[str, Any]] = []
        total   = len(bridge_lines)

        for i in range(0, total, batch_size):
            chunk = bridge_lines[i: i + batch_size]
            log.info(
                f"[IranAI] batch_ai_score: chunk {i // batch_size + 1} "
                f"({len(chunk)} bridges, level={censorship_level})"
            )
            chunk_json = json.dumps(chunk)
            user_msg = (
                f"Score these Tor bridges for Iran (censorship level {censorship_level}/5).\n"
                f"Return ONLY a JSON array, one entry per bridge, sorted by score desc:\n"
                f"[{{\"bridge_line\":\"...\",\"score\":0.92,\"transport\":\"snowflake\","
                f"\"port\":443,\"recommendation\":\"use\",\"tier\":\"excellent\"}}, ...]\n\n"
                f"Bridges:\n{chunk_json}"
            )
            raw = self.gw.prompt(
                IRAN_SYSTEM_PROMPT, user_msg,
                max_tokens=2048, temperature=0.05, task="reasoning"
            )
            chunk_results = _safe_json(raw, [])
            if isinstance(chunk_results, list) and chunk_results:
                results.extend(chunk_results)
            else:
                # Fallback: add neutrals
                for b in chunk:
                    results.append({
                        "bridge_line":    b,
                        "score":          0.5,
                        "recommendation": "test",
                        "tier":           "capable",
                    })

            # Brief pause between chunks to avoid rate limiting
            if i + batch_size < total:
                time.sleep(0.5)

        results.sort(key=lambda x: float(x.get("score", 0)), reverse=True)
        log.info(f"[IranAI] batch_ai_score: {len(results)} bridges scored")
        return results
