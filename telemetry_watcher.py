#!/usr/bin/env python3
"""
telemetry_watcher.py — Centralized Telemetry & Self-Healing Monitor v1.0
═══════════════════════════════════════════════════════════════════════════════

Autonomous telemetry system for the TorShield-IR project. Provides centralized
logging, 24-hour aggregation, DPI event tracking, and self-healing diagnostics.

CAPABILITIES:
  - Asynchronous, fail-safe logging to monitor.log
  - DPI attack event counter and pattern tracking
  - Slot poisoning detection and quarantine logging
  - 24-hour automated daily report generation
  - Self-heal event tracking and correlation
  - Auto-debug trigger on consecutive failures
  - Graceful fail-safe: if log writing fails, system continues without crash
  - Thread-safe operations for concurrent access

DESIGN PRINCIPLES:
  - ADDITIVE ONLY: Does not modify or replace any existing module
  - WRAPPER PATTERN: Wraps around existing architecture seamlessly
  - ZERO CRASH: All I/O wrapped in try/except with graceful degradation
  - ASYNC-SAFE: Uses threading.Lock for concurrent telemetry writes

USAGE:
  from telemetry_watcher import TelemetryWatcher

  watcher = TelemetryWatcher()

  # Log a DPI event
  watcher.log_dpi_event("sni_inspector", "blocked", {"bridge": "obfs4...", "port": 443})

  # Log a slot failure
  watcher.log_slot_failure(3, "CF_API_TOKEN_3", "HTTP 403 Forbidden")

  # Log a self-heal event
  watcher.log_self_heal("auto_switch_provider", {"from": "cerebras", "to": "cf_gateway"})

  # Get 24-hour summary
  summary = watcher.get_24h_summary()

  # Run auto-debug check
  watcher.check_auto_debug()
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("torshield.telemetry")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

DATA_DIR = Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)

MONITOR_LOG_PATH = DATA_DIR / "monitor.log"
TELEMETRY_STATE_PATH = DATA_DIR / "telemetry_state.json"
DAILY_REPORT_PATH = DATA_DIR / "daily_telemetry_report.json"
AUTO_DEBUG_TRIGGER_THRESHOLD = 2  # consecutive model resolution failures trigger auto-debug

# IRST timezone offset (Iran Standard Time = UTC+3:30)
IRST_OFFSET = timedelta(hours=3, minutes=30)
IRST_TZ = timezone(IRST_OFFSET)

# High-censorship hours in IRST (18:00 - 01:00)
HIGH_CENSORSHIP_START = 18  # 18:00 IRST
HIGH_CENSORSHIP_END = 1     # 01:00 IRST (next day)


# ─────────────────────────────────────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DPIEvent:
    """A single DPI detection/evasion event."""
    timestamp: str
    dpi_system: str          # e.g., "sni_inspector", "ja3_fingerprinter"
    action: str              # "blocked", "detected", "evaded", "camouflaged"
    details: Dict[str, Any] = field(default_factory=dict)
    evasion_used: str = ""   # Which evasion technique was used
    success: bool = True     # Whether evasion succeeded


@dataclass
class SlotEvent:
    """A slot failure/recovery event."""
    timestamp: str
    slot_index: int
    env_var: str
    error_type: str         # e.g., "HTTP 403", "HTTP 500", "Timeout", "Circuit Open"
    error_detail: str = ""
    recovered: bool = False
    recovery_method: str = ""


@dataclass
class SelfHealEvent:
    """A self-healing action taken by the system."""
    timestamp: str
    action_type: str        # e.g., "auto_switch_provider", "reset_circuit", "fallback_static"
    details: Dict[str, Any] = field(default_factory=dict)
    success: bool = True
    recovery_time_ms: float = 0.0


@dataclass
class DailyAggregation:
    """24-hour aggregated telemetry report."""
    date: str
    total_dpi_events: int = 0
    dpi_events_blocked: int = 0
    dpi_events_evaded: int = 0
    dpi_events_by_system: Dict[str, int] = field(default_factory=dict)
    total_slot_failures: int = 0
    slots_poisoned: List[int] = field(default_factory=list)
    slots_recovered: List[int] = field(default_factory=list)
    total_self_heal_events: int = 0
    self_heal_by_type: Dict[str, int] = field(default_factory=dict)
    failures_recovered: int = 0
    model_resolution_failures: int = 0
    auto_debug_triggered: int = 0
    peak_censorship_hour_irst: str = ""
    evasion_success_rate: float = 0.0
    uptime_percentage: float = 100.0


# ─────────────────────────────────────────────────────────────────────────────
# Telemetry Watcher
# ─────────────────────────────────────────────────────────────────────────────

class TelemetryWatcher:
    """
    Centralized, fail-safe telemetry system.

    All I/O operations are wrapped in try/except blocks.
    If writing to monitor.log fails (e.g., disk full), the system gracefully
    ignores the error and continues core operations without crashing.
    """

    _instance: Optional["TelemetryWatcher"] = None
    _instance_lock = threading.Lock()

    def __init__(self):
        self._lock = threading.Lock()
        self._dpi_events: List[DPIEvent] = []
        self._slot_events: List[SlotEvent] = []
        self._self_heal_events: List[SelfHealEvent] = []
        self._consecutive_model_failures: int = 0
        self._start_time: float = time.time()
        self._last_report_time: float = time.time()
        self._total_requests: int = 0
        self._successful_requests: int = 0

        # In-memory counters for fast access
        self._counters: Dict[str, int] = defaultdict(int)

        # Load persisted state
        self._load_state()

        log.info("[Telemetry] TelemetryWatcher initialized — fail-safe mode active")

    @classmethod
    def instance(cls) -> "TelemetryWatcher":
        """Get or create the singleton TelemetryWatcher instance."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    # ── Core Logging Methods ────────────────────────────────────────────────

    def log_dpi_event(
        self,
        dpi_system: str,
        action: str,
        details: Optional[Dict[str, Any]] = None,
        evasion_used: str = "",
        success: bool = True,
    ) -> None:
        """
        Log a DPI detection/evasion event.
        Gracefully fails if logging is not possible.
        """
        try:
            event = DPIEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                dpi_system=dpi_system,
                action=action,
                details=details or {},
                evasion_used=evasion_used,
                success=success,
            )

            with self._lock:
                self._dpi_events.append(event)
                self._counters["dpi_total"] += 1
                if action == "blocked":
                    self._counters["dpi_blocked"] += 1
                elif action == "evaded":
                    self._counters["dpi_evaded"] += 1
                elif action == "camouflaged":
                    self._counters["dpi_camouflaged"] += 1

                # Track by DPI system
                sys_key = f"dpi_sys_{dpi_system}"
                self._counters[sys_key] += 1

            self._write_monitor_log(
                f"DPI_EVENT | {dpi_system} | {action} | "
                f"evasion={evasion_used} | success={success}"
            )
            self._persist_state()

        except Exception as e:
            # GRACEFUL FAIL-SAFE: ignore logging errors
            try:
                log.debug(f"[Telemetry] Failed to log DPI event: {e}")
            except Exception:
                pass

    def log_slot_failure(
        self,
        slot_index: int,
        env_var: str,
        error_type: str,
        error_detail: str = "",
    ) -> None:
        """
        Log a slot failure event.
        Tracks slot poisoning for circuit breaker integration.
        """
        try:
            event = SlotEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                slot_index=slot_index,
                env_var=env_var,
                error_type=error_type,
                error_detail=error_detail,
            )

            with self._lock:
                self._slot_events.append(event)
                self._counters["slot_failures"] += 1
                slot_key = f"slot_{slot_index}_failures"
                self._counters[slot_key] += 1

            self._write_monitor_log(
                f"SLOT_FAILURE | Slot {slot_index} | {env_var} | "
                f"{error_type} | {error_detail}"
            )
            self._persist_state()

        except Exception as e:
            try:
                log.debug(f"[Telemetry] Failed to log slot failure: {e}")
            except Exception:
                pass

    def log_slot_recovery(
        self,
        slot_index: int,
        env_var: str,
        recovery_method: str = "circuit_reset",
    ) -> None:
        """Log a slot recovery event."""
        try:
            event = SlotEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                slot_index=slot_index,
                env_var=env_var,
                error_type="recovered",
                recovered=True,
                recovery_method=recovery_method,
            )

            with self._lock:
                self._slot_events.append(event)
                self._counters["slot_recoveries"] += 1

            self._write_monitor_log(
                f"SLOT_RECOVERY | Slot {slot_index} | {env_var} | "
                f"method={recovery_method}"
            )
            self._persist_state()

        except Exception as e:
            try:
                log.debug(f"[Telemetry] Failed to log slot recovery: {e}")
            except Exception:
                pass

    def log_self_heal(
        self,
        action_type: str,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
        recovery_time_ms: float = 0.0,
    ) -> None:
        """
        Log a self-healing event.
        Tracks autonomous recovery actions taken by the system.
        """
        try:
            event = SelfHealEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                action_type=action_type,
                details=details or {},
                success=success,
                recovery_time_ms=recovery_time_ms,
            )

            with self._lock:
                self._self_heal_events.append(event)
                self._counters["self_heal_total"] += 1
                heal_key = f"self_heal_{action_type}"
                self._counters[heal_key] += 1
                if success:
                    self._counters["failures_recovered"] += 1

            self._write_monitor_log(
                f"SELF_HEAL | {action_type} | success={success} | "
                f"recovery_time={recovery_time_ms:.1f}ms"
            )
            self._persist_state()

        except Exception as e:
            try:
                log.debug(f"[Telemetry] Failed to log self-heal event: {e}")
            except Exception:
                pass

    def log_model_resolution_failure(self) -> None:
        """
        Track model resolution failures.
        Triggers auto-debug after consecutive failures exceed threshold.
        """
        try:
            with self._lock:
                self._consecutive_model_failures += 1
                self._counters["model_resolution_failures"] += 1

            self._write_monitor_log(
                f"MODEL_FAILURE | consecutive={self._consecutive_model_failures}"
            )

            # Check auto-debug trigger
            if self._consecutive_model_failures >= AUTO_DEBUG_TRIGGER_THRESHOLD:
                self._trigger_auto_debug()

        except Exception as e:
            try:
                log.debug(f"[Telemetry] Failed to log model failure: {e}")
            except Exception:
                pass

    def log_model_resolution_success(self) -> None:
        """Reset consecutive model failure counter on success."""
        try:
            with self._lock:
                self._consecutive_model_failures = 0
        except Exception:
            pass

    def log_request(self, success: bool) -> None:
        """Track overall request success/failure for uptime calculation."""
        try:
            with self._lock:
                self._total_requests += 1
                if success:
                    self._successful_requests += 1
        except Exception:
            pass

    # ── 24-Hour Aggregation ─────────────────────────────────────────────────

    def get_24h_summary(self) -> DailyAggregation:
        """
        Generate a 24-hour aggregated telemetry report.
        Covers DPI events, slot failures, self-heal events, and uptime.
        """
        try:
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(hours=24)
            today_str = now.strftime("%Y-%m-%d")

            with self._lock:
                # Filter events from last 24 hours
                recent_dpi = [
                    e for e in self._dpi_events
                    if self._parse_ts(e.timestamp) > cutoff
                ]
                recent_slots = [
                    e for e in self._slot_events
                    if self._parse_ts(e.timestamp) > cutoff
                ]
                recent_heals = [
                    e for e in self._self_heal_events
                    if self._parse_ts(e.timestamp) > cutoff
                ]

            # DPI aggregation
            dpi_blocked = sum(1 for e in recent_dpi if e.action == "blocked")
            dpi_evaded = sum(1 for e in recent_dpi if e.action in ("evaded", "camouflaged"))
            dpi_by_system: Dict[str, int] = defaultdict(int)
            for e in recent_dpi:
                dpi_by_system[e.dpi_system] += 1

            # Peak censorship hour (based on DPI event density by IRST hour)
            hour_counts: Dict[int, int] = defaultdict(int)
            for e in recent_dpi:
                try:
                    dt = self._parse_ts(e.timestamp)
                    iran_hour = (dt + IRST_OFFSET).hour
                    hour_counts[iran_hour] += 1
                except Exception:
                    pass

            peak_hour = ""
            if hour_counts:
                peak_h = max(hour_counts, key=hour_counts.get)  # type: ignore[arg-type]
                peak_hour = f"{peak_h:02d}:00 IRST"

            # Slot aggregation
            poisoned_slots = list(set(
                e.slot_index for e in recent_slots
                if not e.recovered
            ))
            recovered_slots = list(set(
                e.slot_index for e in recent_slots
                if e.recovered
            ))

            # Self-heal aggregation
            heal_by_type: Dict[str, int] = defaultdict(int)
            for e in recent_heals:
                heal_by_type[e.action_type] += 1
            failures_recovered = sum(1 for e in recent_heals if e.success)

            # Evasion success rate
            total_evasion_attempts = dpi_blocked + dpi_evaded
            evasion_rate = (
                dpi_evaded / total_evasion_attempts
                if total_evasion_attempts > 0
                else 1.0
            )

            # Uptime
            uptime = (
                self._successful_requests / self._total_requests * 100.0
                if self._total_requests > 0
                else 100.0
            )

            aggregation = DailyAggregation(
                date=today_str,
                total_dpi_events=len(recent_dpi),
                dpi_events_blocked=dpi_blocked,
                dpi_events_evaded=dpi_evaded,
                dpi_events_by_system=dict(dpi_by_system),
                total_slot_failures=len(recent_slots),
                slots_poisoned=sorted(poisoned_slots),
                slots_recovered=sorted(recovered_slots),
                total_self_heal_events=len(recent_heals),
                self_heal_by_type=dict(heal_by_type),
                failures_recovered=failures_recovered,
                model_resolution_failures=self._counters.get("model_resolution_failures", 0),
                auto_debug_triggered=self._counters.get("auto_debug_triggered", 0),
                peak_censorship_hour_irst=peak_hour,
                evasion_success_rate=round(evasion_rate, 4),
                uptime_percentage=round(uptime, 2),
            )

            # Persist daily report
            self._save_daily_report(aggregation)

            return aggregation

        except Exception as e:
            log.warning(f"[Telemetry] 24h summary generation failed: {e}")
            return DailyAggregation(date=datetime.now(timezone.utc).strftime("%Y-%m-%d"))

    def _save_daily_report(self, aggregation: DailyAggregation) -> None:
        """Persist the daily telemetry report to disk."""
        try:
            report_data = asdict(aggregation)
            DAILY_REPORT_PATH.write_text(
                json.dumps(report_data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as e:
            # GRACEFUL FAIL-SAFE: ignore write errors
            try:
                log.debug(f"[Telemetry] Failed to save daily report: {e}")
            except Exception:
                pass

    # ── Auto-Debug Trigger ──────────────────────────────────────────────────

    def check_auto_debug(self) -> bool:
        """
        Check if auto-debug should be triggered based on telemetry data.
        Returns True if auto-debug was triggered.
        """
        try:
            if self._consecutive_model_failures >= AUTO_DEBUG_TRIGGER_THRESHOLD:
                self._trigger_auto_debug()
                return True
        except Exception:
            pass
        return False

    def _trigger_auto_debug(self) -> None:
        """
        Trigger deep self-diagnostic check.
        Checks environment variables, proxy health, NIN/DPI state.
        """
        try:
            self._counters["auto_debug_triggered"] += 1
            self._write_monitor_log("AUTO_DEBUG_TRIGGERED | Starting deep self-diagnostic")

            # Run auto-debug system if available
            try:
                from auto_debug_system import AutoDebugSystem
                ads = AutoDebugSystem()
                report = ads.run_full_diagnosis()

                if report.get("summary", {}).get("errors", 0) > 0:
                    self._write_monitor_log(
                        f"AUTO_DEBUG_RESULT | errors={report['summary']['errors']} | "
                        f"warnings={report['summary']['warnings']}"
                    )
                    # Attempt auto-fix
                    fixed = ads.auto_fix_all()
                    if fixed:
                        self.log_self_heal(
                            "auto_debug_fix",
                            {"errors_fixed": len(fixed)},
                            success=True,
                        )
                else:
                    self._write_monitor_log("AUTO_DEBUG_RESULT | All checks passed")
            except ImportError:
                self._write_monitor_log("AUTO_DEBUG_RESULT | auto_debug_system not available")

            # Check environment variables
            self._check_env_vars()

            # Check proxy health
            self._check_proxy_health()

            # Check NIN/DPI state
            self._check_nin_dpi_state()

            # Reset counter after diagnostic
            self._consecutive_model_failures = 0

        except Exception as e:
            try:
                self._write_monitor_log(f"AUTO_DEBUG_FAILED | {e}")
            except Exception:
                pass

    def _check_env_vars(self) -> None:
        """Validate critical environment variables."""
        try:
            critical_vars = []
            for i in range(1, 12):
                critical_vars.extend([
                    f"CF_ACCOUNT_ID_{i}",
                    f"CF_API_TOKEN_{i}",
                    f"CF_AI_GATEWAY_URL_{i}",
                ])

            missing = []
            empty = []
            for var in critical_vars:
                val = os.environ.get(var)
                if val is None:
                    missing.append(var)
                elif not val.strip():
                    empty.append(var)

            if missing:
                self._write_monitor_log(
                    f"ENV_CHECK | Missing env vars: {', '.join(missing[:5])}"
                )
            if empty:
                self._write_monitor_log(
                    f"ENV_CHECK | Empty env vars: {', '.join(empty[:5])} "
                    f"(total: {len(empty)})"
                )

        except Exception:
            pass

    def _check_proxy_health(self) -> None:
        """Check proxy connectivity if configured."""
        try:
            http_proxy = os.environ.get("HTTP_PROXY", "")
            https_proxy = os.environ.get("HTTPS_PROXY", "")

            if http_proxy or https_proxy:
                import urllib.request
                import urllib.error

                proxy_url = https_proxy or http_proxy
                try:
                    proxy_handler = urllib.request.ProxyHandler({
                        "https": proxy_url,
                        "http": proxy_url,
                    })
                    opener = urllib.request.build_opener(proxy_handler)
                    # Quick connectivity check
                    req = urllib.request.Request(
                        "https://www.cloudflare.com",
                        headers={"User-Agent": "TorShield-IR/1.0"},
                        method="HEAD",
                    )
                    opener.open(req, timeout=5)
                    self._write_monitor_log("PROXY_CHECK | Proxy healthy")
                except Exception as e:
                    self._write_monitor_log(f"PROXY_CHECK | Proxy unhealthy: {e}")
                    self.log_self_heal(
                        "proxy_warning",
                        {"proxy": proxy_url, "error": str(e)},
                        success=False,
                    )
        except Exception:
            pass

    def _check_nin_dpi_state(self) -> None:
        """Check current NIN/DPI state using existing modules."""
        try:
            from iran_smart_anti_filter import IranSmartAntiFilter
            saf = IranSmartAntiFilter()
            status = saf.get_status()
            censorship_level = status.get("censorship", {}).get("level", 0)
            nin_active = status.get("censorship", {}).get("nin_active", False)

            self._write_monitor_log(
                f"NIN_DPI_CHECK | Level={censorship_level} | NIN={nin_active}"
            )

            if nin_active:
                self.log_dpi_event(
                    "nin_internet_cut",
                    "detected",
                    {"censorship_level": censorship_level},
                )
        except ImportError:
            try:
                self._write_monitor_log("NIN_DPI_CHECK | Module not available")
            except Exception:
                pass
        except Exception as e:
            try:
                self._write_monitor_log(f"NIN_DPI_CHECK | Error: {e}")
            except Exception:
                pass

    # ── IRST Time Utilities ─────────────────────────────────────────────────

    @staticmethod
    def get_iran_time() -> datetime:
        """Get current Iran Standard Time (IRST)."""
        return datetime.now(IRST_TZ)

    @staticmethod
    def is_high_censorship_hours() -> bool:
        """
        Check if current IRST time is within high-censorship hours (18:00 - 01:00).
        During these hours, DPI evasion aggressiveness should be increased.
        """
        iran_hour = datetime.now(IRST_TZ).hour
        if HIGH_CENSORSHIP_START <= iran_hour <= 23:
            return True
        if 0 <= iran_hour < HIGH_CENSORSHIP_END:
            return True
        return False

    @staticmethod
    def get_censorship_intensity() -> str:
        """
        Get current censorship intensity level based on IRST time.
        Returns: "ultra_stealth", "high_stealth", "normal"
        """
        iran_hour = datetime.now(IRST_TZ).hour
        # Peak hours: 20:00 - 23:00 IRST
        if 20 <= iran_hour <= 23:
            return "ultra_stealth"
        # High censorship: 18:00 - 01:00 IRST
        elif 18 <= iran_hour <= 23 or (0 <= iran_hour < 1):
            return "high_stealth"
        # Low censorship: 03:00 - 06:00 IRST
        elif 3 <= iran_hour <= 6:
            return "relaxed"
        else:
            return "normal"

    # ── Internal Helpers ────────────────────────────────────────────────────

    def _write_monitor_log(self, message: str) -> None:
        """
        Write a message to monitor.log.
        GRACEFUL FAIL-SAFE: if writing fails, silently continue.
        """
        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            log_line = f"[{timestamp}] {message}\n"

            with self._lock:
                with open(MONITOR_LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(log_line)

                # Rotate log if too large (> 10 MB)
                try:
                    if MONITOR_LOG_PATH.stat().st_size > 10 * 1024 * 1024:
                        self._rotate_log()
                except Exception:
                    pass

        except Exception:
            # GRACEFUL FAIL-SAFE: disk full, permission error, etc.
            pass

    def _rotate_log(self) -> None:
        """Rotate monitor.log when it exceeds size limit."""
        try:
            backup_path = DATA_DIR / "monitor.log.1"
            if backup_path.exists():
                backup_path.unlink()
            MONITOR_LOG_PATH.rename(backup_path)
            self._write_monitor_log("LOG_ROTATION | monitor.log rotated")
        except Exception:
            pass

    @staticmethod
    def _parse_ts(ts_str: str) -> datetime:
        """Parse ISO timestamp string."""
        try:
            return datetime.fromisoformat(ts_str)
        except Exception:
            return datetime.now(timezone.utc)

    def _persist_state(self) -> None:
        """Persist telemetry state to disk for crash recovery."""
        try:
            with self._lock:
                state = {
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                    "counters": dict(self._counters),
                    "consecutive_model_failures": self._consecutive_model_failures,
                    "total_requests": self._total_requests,
                    "successful_requests": self._successful_requests,
                    "start_time": self._start_time,
                    # Keep last 100 events of each type for crash recovery
                    "recent_dpi_events": [asdict(e) for e in self._dpi_events[-100:]],
                    "recent_slot_events": [asdict(e) for e in self._slot_events[-100:]],
                    "recent_self_heal_events": [asdict(e) for e in self._self_heal_events[-100:]],
                }

            TELEMETRY_STATE_PATH.write_text(
                json.dumps(state, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            # GRACEFUL FAIL-SAFE
            pass

    def _load_state(self) -> None:
        """Load persisted state from disk for crash recovery."""
        try:
            if not TELEMETRY_STATE_PATH.exists():
                return

            data = json.loads(TELEMETRY_STATE_PATH.read_text(encoding="utf-8"))

            self._counters = defaultdict(int, data.get("counters", {}))
            self._consecutive_model_failures = data.get("consecutive_model_failures", 0)
            self._total_requests = data.get("total_requests", 0)
            self._successful_requests = data.get("successful_requests", 0)

            # Restore recent events
            for e_data in data.get("recent_dpi_events", []):
                try:
                    self._dpi_events.append(DPIEvent(**e_data))
                except Exception:
                    pass
            for e_data in data.get("recent_slot_events", []):
                try:
                    self._slot_events.append(SlotEvent(**e_data))
                except Exception:
                    pass
            for e_data in data.get("recent_self_heal_events", []):
                try:
                    self._self_heal_events.append(SelfHealEvent(**e_data))
                except Exception:
                    pass

            log.info(
                f"[Telemetry] Restored state: {len(self._dpi_events)} DPI events, "
                f"{len(self._slot_events)} slot events, "
                f"{len(self._self_heal_events)} heal events"
            )

        except Exception as e:
            log.warning(f"[Telemetry] Failed to load state: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get current telemetry status summary."""
        try:
            return {
                "monitor_log_path": str(MONITOR_LOG_PATH),
                "total_dpi_events": self._counters.get("dpi_total", 0),
                "dpi_blocked": self._counters.get("dpi_blocked", 0),
                "dpi_evaded": self._counters.get("dpi_evaded", 0),
                "dpi_camouflaged": self._counters.get("dpi_camouflaged", 0),
                "total_slot_failures": self._counters.get("slot_failures", 0),
                "total_self_heal_events": self._counters.get("self_heal_total", 0),
                "failures_recovered": self._counters.get("failures_recovered", 0),
                "model_resolution_failures": self._counters.get("model_resolution_failures", 0),
                "consecutive_model_failures": self._consecutive_model_failures,
                "auto_debug_triggered": self._counters.get("auto_debug_triggered", 0),
                "iran_time": self.get_iran_time().strftime("%H:%M IRST"),
                "is_high_censorship_hours": self.is_high_censorship_hours(),
                "censorship_intensity": self.get_censorship_intensity(),
                "uptime_percentage": round(
                    self._successful_requests / max(self._total_requests, 1) * 100, 2
                ),
            }
        except Exception:
            return {"error": "telemetry_status_unavailable"}

    def get_poisoned_slots(self) -> List[int]:
        """Get list of currently poisoned (failed) slot indices."""
        try:
            with self._lock:
                poisoned = set()
                for e in self._slot_events:
                    if not e.recovered:
                        poisoned.add(e.slot_index)
                return sorted(poisoned)
        except Exception:
            return []


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience functions
# ─────────────────────────────────────────────────────────────────────────────

def get_telemetry() -> TelemetryWatcher:
    """Get the singleton TelemetryWatcher instance."""
    return TelemetryWatcher.instance()


def log_dpi_event(
    dpi_system: str,
    action: str,
    details: Optional[Dict[str, Any]] = None,
    evasion_used: str = "",
    success: bool = True,
) -> None:
    """Module-level DPI event logging."""
    get_telemetry().log_dpi_event(dpi_system, action, details, evasion_used, success)


def log_slot_failure(slot_index: int, env_var: str, error_type: str, error_detail: str = "") -> None:
    """Module-level slot failure logging."""
    get_telemetry().log_slot_failure(slot_index, env_var, error_type, error_detail)


def log_self_heal(
    action_type: str,
    details: Optional[Dict[str, Any]] = None,
    success: bool = True,
    recovery_time_ms: float = 0.0,
) -> None:
    """Module-level self-heal event logging."""
    get_telemetry().log_self_heal(action_type, details, success, recovery_time_ms)


def generate_daily_report() -> DailyAggregation:
    """Generate and return the 24-hour telemetry report."""
    return get_telemetry().get_24h_summary()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """CLI entry point for telemetry watcher."""
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="TorShield-IR Telemetry Watcher")
    parser.add_argument("--status", action="store_true", help="Show current telemetry status")
    parser.add_argument("--report", action="store_true", help="Generate 24h report")
    parser.add_argument("--check-debug", action="store_true", help="Check if auto-debug should trigger")
    parser.add_argument("--iran-time", action="store_true", help="Show current Iran time and censorship intensity")
    args = parser.parse_args()

    watcher = TelemetryWatcher()

    if args.status:
        status = watcher.get_status()
        print(json.dumps(status, indent=2, ensure_ascii=False))
    elif args.report:
        report = watcher.get_24h_summary()
        print(json.dumps(asdict(report), indent=2, ensure_ascii=False))
    elif args.check_debug:
        should_debug = watcher.check_auto_debug()
        print(f"Auto-debug triggered: {should_debug}")
        print(f"Consecutive model failures: {watcher._consecutive_model_failures}")
    elif args.iran_time:
        iran_time = watcher.get_iran_time()
        intensity = watcher.get_censorship_intensity()
        high_censorship = watcher.is_high_censorship_hours()
        print(f"Iran Time: {iran_time.strftime('%H:%M IRST')}")
        print(f"Censorship Intensity: {intensity}")
        print(f"High Censorship Hours: {high_censorship}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
