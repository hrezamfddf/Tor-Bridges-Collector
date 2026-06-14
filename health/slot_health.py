#!/usr/bin/env python3
"""
slot_health.py — Slot Health Probes and Scoring v1.0
═══════════════════════════════════════════════════════════════════════════════

Health monitoring system for CF AI Gateway slots. Probes each slot endpoint,
tracks latency and success rates, and provides health scores for slot selection.

DESIGN PRINCIPLES:
  - ADDITIVE ONLY: Does not modify existing health_check.py
  - WRAPPER PATTERN: Enhances existing health monitoring
  - ZERO CRASH: All operations wrapped in try/except
  - Feature-flagged: ENABLE_ENDPOINT_VALIDATION=true
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("torshield.slot_health")


@dataclass
class SlotHealthScore:
    """Health score for a single slot."""
    slot_index: int
    is_healthy: bool = False
    latency_ms: float = 0.0
    success_rate: float = 0.0
    error_rate: float = 0.0
    last_probe_time: float = 0.0
    last_error: str = ""
    consecutive_successes: int = 0
    consecutive_failures: int = 0
    total_probes: int = 0
    total_successes: int = 0
    total_failures: int = 0

    @property
    def health_score(self) -> float:
        """Composite health score 0.0-1.0."""
        if self.total_probes == 0:
            return 0.5  # Unknown health
        base = self.success_rate
        latency_penalty = min(self.latency_ms / 5000.0, 0.3)
        failure_penalty = min(self.consecutive_failures * 0.1, 0.3)
        return max(0.0, base - latency_penalty - failure_penalty)


class SlotHealthMonitor:
    """
    Monitors health of CF AI Gateway slots.
    
    Probes each slot endpoint periodically and tracks:
    - Latency (ms)
    - Success rate
    - Error patterns
    - Consecutive successes/failures
    """

    _instance: Optional["SlotHealthMonitor"] = None
    _instance_lock = threading.Lock()

    def __init__(self):
        self._lock = threading.Lock()
        self._scores: Dict[int, SlotHealthScore] = {}
        self._probe_timeout = int(os.getenv("HEALTH_PROBE_TIMEOUT", "8"))

        # Structured logging integration
        try:
            from monitoring.structured_logger import get_structured_logger
            self._logger = get_structured_logger()
        except ImportError:
            self._logger = None

    @classmethod
    def instance(cls) -> "SlotHealthMonitor":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def probe_slot(
        self,
        slot_index: int,
        gateway_url: str,
        api_token: str = "",
    ) -> SlotHealthScore:
        """Probe a single slot's health by sending a lightweight request."""
        try:
            # Build the health check URL (use /compat/ path)
            base_url = gateway_url.split("/compat/")[0].split("/workers-ai/")[0].rstrip("/")
            health_url = base_url + "/compat/chat/completions"

            t0 = time.monotonic()

            # Send a minimal chat request to test the endpoint
            payload = json.dumps({
                "model": "@cf/meta/llama-3.2-1b-instruct",
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 5,
                "temperature": 0.1,
                "stream": False,
            }).encode("utf-8")

            headers = {
                "Content-Type": "application/json",
                "User-Agent": "TorShield-HealthProbe/1.0",
            }
            if api_token:
                headers["Authorization"] = f"Bearer {api_token}"

            req = urllib.request.Request(
                health_url, data=payload, headers=headers, method="POST"
            )

            try:
                with urllib.request.urlopen(req, timeout=self._probe_timeout) as resp:
                    latency = (time.monotonic() - t0) * 1000
                    result = json.loads(resp.read().decode("utf-8"))

                    # Check for valid response
                    has_content = False
                    if isinstance(result, dict):
                        choices = result.get("choices", [])
                        if choices:
                            content = choices[0].get("message", {}).get("content", "")
                            has_content = bool(content.strip())

                    score = SlotHealthScore(
                        slot_index=slot_index,
                        is_healthy=has_content,
                        latency_ms=latency,
                        last_probe_time=time.time(),
                        total_probes=1,
                        total_successes=1 if has_content else 0,
                        total_failures=0 if has_content else 1,
                        consecutive_successes=1 if has_content else 0,
                    )
                    if has_content:
                        score.success_rate = 1.0
                    else:
                        score.success_rate = 0.0
                        score.last_error = "Empty response content"

            except urllib.error.HTTPError as e:
                latency = (time.monotonic() - t0) * 1000
                error_body = ""
                try:
                    error_body = e.read().decode("utf-8", errors="replace")[:200]
                except Exception:
                    pass

                score = SlotHealthScore(
                    slot_index=slot_index,
                    is_healthy=False,
                    latency_ms=latency,
                    last_probe_time=time.time(),
                    last_error=f"HTTP {e.code}: {error_body}",
                    total_probes=1,
                    total_successes=0,
                    total_failures=1,
                    consecutive_failures=1,
                )

            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as e:
                latency = (time.monotonic() - t0) * 1000
                score = SlotHealthScore(
                    slot_index=slot_index,
                    is_healthy=False,
                    latency_ms=latency,
                    last_probe_time=time.time(),
                    last_error=f"Network error: {e}",
                    total_probes=1,
                    total_successes=0,
                    total_failures=1,
                    consecutive_failures=1,
                )

            # Update running score
            with self._lock:
                existing = self._scores.get(slot_index)
                if existing:
                    existing.total_probes += score.total_probes
                    existing.total_successes += score.total_successes
                    existing.total_failures += score.total_failures
                    existing.last_probe_time = score.last_probe_time
                    existing.latency_ms = (
                        0.5 * score.latency_ms + 0.5 * existing.latency_ms
                    )
                    existing.success_rate = existing.total_successes / existing.total_probes
                    existing.error_rate = existing.total_failures / existing.total_probes
                    existing.is_healthy = score.is_healthy

                    if score.is_healthy:
                        existing.consecutive_successes += 1
                        existing.consecutive_failures = 0
                    else:
                        existing.consecutive_failures += 1
                        existing.consecutive_successes = 0
                        existing.last_error = score.last_error
                else:
                    self._scores[slot_index] = score

            return self._scores[slot_index]

        except Exception as e:
            logger.error(f"[SlotHealth] probe_slot error for slot {slot_index}: {e}")
            return SlotHealthScore(
                slot_index=slot_index,
                is_healthy=False,
                last_error=str(e),
            )

    def probe_all_slots(self) -> Dict[int, SlotHealthScore]:
        """Probe all configured CF slots."""
        for i in range(1, 12):
            gateway_url = os.getenv(f"CF_AI_GATEWAY_URL_{i}", "").strip()
            api_token = os.getenv(f"CF_API_TOKEN_{i}", "").strip()
            if gateway_url and api_token:
                self.probe_slot(i, gateway_url, api_token)
        return self._scores

    def get_healthy_slots(self) -> List[int]:
        """Get list of healthy slot indices."""
        with self._lock:
            return [
                i for i, s in self._scores.items() if s.is_healthy
            ]

    def get_status(self) -> Dict:
        """Get health monitoring status."""
        with self._lock:
            healthy = sum(1 for s in self._scores.values() if s.is_healthy)
            total = len(self._scores)
            return {
                "total_slots_monitored": total,
                "healthy_slots": healthy,
                "unhealthy_slots": total - healthy,
                "slots": {
                    str(i): {
                        "healthy": s.is_healthy,
                        "latency_ms": round(s.latency_ms, 1),
                        "success_rate": round(s.success_rate, 3),
                        "health_score": round(s.health_score, 3),
                        "last_error": s.last_error,
                        "consecutive_failures": s.consecutive_failures,
                    }
                    for i, s in self._scores.items()
                },
            }


def get_health_monitor() -> SlotHealthMonitor:
    """Get the singleton SlotHealthMonitor instance."""
    return SlotHealthMonitor.instance()
