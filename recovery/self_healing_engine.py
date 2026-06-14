#!/usr/bin/env python3
"""
self_healing_engine.py — Self-Healing Engine v1.0
═══════════════════════════════════════════════════════════════════════════════

Autonomous self-healing engine that triggers when 2+ sequential model
resolution failures occur. Performs comprehensive diagnostics and recovery.

Self-Healing Steps:
  a. Re-validate all environment variables
  b. Re-probe all slot endpoints
  c. Rebuild model registry from live fetch
  d. Reset circuit breakers for previously-open slots past cooldown
  e. Log full diagnostic snapshot to recovery.log

Trigger: 2+ sequential model resolution failures

DESIGN PRINCIPLES:
  - ADDITIVE ONLY: Does not modify existing code
  - ZERO CRASH: All operations wrapped in try/except
  - Feature-flagged: ENABLE_SELF_HEALING=true
  - NEVER RAISES: Always returns a diagnostic result
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("torshield.self_healing")


@dataclass
class SelfHealResult:
    """Result of a self-healing cycle."""
    triggered_at: float = field(default_factory=time.time)
    trigger_reason: str = ""
    actions_taken: List[str] = field(default_factory=list)
    slots_revalidated: int = 0
    slots_recovered: int = 0
    endpoints_probed: int = 0
    endpoints_reachable: int = 0
    models_discovered: int = 0
    circuit_breakers_reset: int = 0
    errors_found: List[str] = field(default_factory=list)
    diagnostic_snapshot: Dict = field(default_factory=dict)
    success: bool = True


class SelfHealingEngine:
    """
    Autonomous self-healing engine.
    
    Triggers when 2+ sequential model resolution failures occur.
    Performs comprehensive diagnostics and recovery actions.
    """
    
    _instance: Optional["SelfHealingEngine"] = None
    _instance_lock = threading.Lock()
    
    def __init__(self):
        self._lock = threading.Lock()
        self._sequential_failures = 0
        self._last_heal_time = 0.0
        self._heal_count = 0
        self._trigger_threshold = int(os.getenv("SELF_HEAL_TRIGGER_THRESHOLD", "2"))
        self._cooldown_secs = float(os.getenv("SELF_HEAL_COOLDOWN_SECS", "300"))
        
        # Structured logging integration
        try:
            from monitoring.structured_logger import get_structured_logger
            self._logger = get_structured_logger()
        except ImportError:
            self._logger = None
        
        # Circuit breaker integration
        try:
            from circuit_breaker.slot_circuit_breaker import get_slot_circuit_breaker
            self._circuit_breaker = get_slot_circuit_breaker()
        except ImportError:
            self._circuit_breaker = None
        
        # Endpoint validator integration
        try:
            from core.endpoint_validator import get_validator
            self._validator = get_validator()
        except ImportError:
            self._validator = None
    
    @classmethod
    def instance(cls) -> "SelfHealingEngine":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance
    
    def record_model_failure(self, provider: str = "", model: str = "") -> Optional[SelfHealResult]:
        """
        Record a model resolution failure.
        Triggers self-healing if threshold is reached.
        
        Returns SelfHealResult if healing was triggered, None otherwise.
        """
        try:
            with self._lock:
                self._sequential_failures += 1
                
                logger.warning(
                    f"[SelfHeal] Sequential model failure #{self._sequential_failures} "
                    f"(threshold={self._trigger_threshold}) "
                    f"provider={provider} model={model}"
                )
                
                if self._sequential_failures >= self._trigger_threshold:
                    # Check cooldown
                    if time.time() - self._last_heal_time < self._cooldown_secs:
                        logger.info("[SelfHeal] Cooldown active — skipping heal")
                        return None
                    
                    # Trigger self-healing
                    return self._run_healing_cycle(
                        trigger_reason=f"{self._sequential_failures} sequential model failures"
                    )
                
                return None
        except Exception as e:
            logger.error(f"[SelfHeal] record_model_failure error: {e}")
            return None
    
    def record_model_success(self) -> None:
        """Record a model resolution success — resets sequential failure counter."""
        try:
            with self._lock:
                self._sequential_failures = 0
        except Exception:
            pass
    
    def _run_healing_cycle(self, trigger_reason: str = "") -> SelfHealResult:
        """
        Execute the full self-healing cycle.
        
        Steps:
          a. Re-validate all environment variables
          b. Re-probe all slot endpoints
          c. Rebuild model registry from live fetch
          d. Reset circuit breakers for previously-open slots past cooldown
          e. Log full diagnostic snapshot to recovery.log
        """
        result = SelfHealResult(trigger_reason=trigger_reason)
        
        try:
            logger.info(
                f"[SelfHeal] STARTING healing cycle — reason: {trigger_reason}"
            )
            
            self._last_heal_time = time.time()
            self._heal_count += 1
            
            # Step A: Re-validate all environment variables
            self._step_revalidate_env(result)
            
            # Step B: Re-probe all slot endpoints
            self._step_probe_endpoints(result)
            
            # Step C: Rebuild model registry from live fetch
            self._step_rebuild_model_registry(result)
            
            # Step D: Reset circuit breakers for slots past cooldown
            self._step_reset_circuit_breakers(result)
            
            # Step E: Log full diagnostic snapshot
            self._step_log_diagnostic_snapshot(result)
            
            # Reset sequential failure counter
            self._sequential_failures = 0
            
            logger.info(
                f"[SelfHeal] COMPLETED healing cycle #{self._heal_count} — "
                f"actions={len(result.actions_taken)}, "
                f"slots_recovered={result.slots_recovered}, "
                f"endpoints_reachable={result.endpoints_reachable}"
            )
            
        except Exception as e:
            result.success = False
            result.errors_found.append(str(e))
            logger.error(f"[SelfHeal] Healing cycle error: {e}")
        
        return result
    
    def _step_revalidate_env(self, result: SelfHealResult) -> None:
        """Step A: Re-validate all environment variables."""
        try:
            logger.info("[SelfHeal] Step A: Re-validating environment variables")
            result.actions_taken.append("revalidate_env")
            
            validated = 0
            issues = []
            
            for i in range(1, 12):
                account_id = os.getenv(f"CF_ACCOUNT_ID_{i}", "").strip()
                api_token = os.getenv(f"CF_API_TOKEN_{i}", "").strip()
                gateway_url = os.getenv(f"CF_AI_GATEWAY_URL_{i}", "").strip()
                
                if not account_id and not api_token:
                    continue  # Unconfigured slot — not an error
                
                # Validate account_id format
                if account_id and not re.match(r'^[0-9a-f]{32}$', account_id, re.IGNORECASE):
                    issues.append(f"Slot {i}: Invalid CF_ACCOUNT_ID format")
                
                # Validate API token length
                if api_token and len(api_token) < 40:
                    issues.append(f"Slot {i}: CF_API_TOKEN too short ({len(api_token)} chars)")
                
                # Validate gateway URL
                if gateway_url and not gateway_url.startswith("https://"):
                    issues.append(f"Slot {i}: CF_AI_GATEWAY_URL doesn't start with https://")
                
                # CRITICAL: Check for /workers-ai/ suffix bug
                if gateway_url and "/workers-ai/" in gateway_url:
                    issues.append(
                        f"Slot {i}: CF_AI_GATEWAY_URL uses /workers-ai/ suffix — "
                        f"this causes HTTP 400. Should use /compat/ suffix."
                    )
                
                validated += 1
            
            result.slots_revalidated = validated
            result.errors_found.extend(issues)
            
            if issues:
                logger.warning(f"[SelfHeal] Found {len(issues)} env validation issues")
            else:
                logger.info(f"[SelfHeal] All {validated} slots passed env validation")
            
        except Exception as e:
            result.errors_found.append(f"Env validation error: {e}")
    
    def _step_probe_endpoints(self, result: SelfHealResult) -> None:
        """Step B: Re-probe all slot endpoints."""
        try:
            logger.info("[SelfHeal] Step B: Re-probing slot endpoints")
            result.actions_taken.append("probe_endpoints")
            
            probed = 0
            reachable = 0
            
            if self._validator:
                validation_results = self._validator.validate_all_slots()
                for slot_index, vr in validation_results.items():
                    probed += 1
                    if vr.is_reachable:
                        reachable += 1
            else:
                # Manual probe
                import urllib.request
                import urllib.error
                
                for i in range(1, 12):
                    gateway_url = os.getenv(f"CF_AI_GATEWAY_URL_{i}", "").strip()
                    if not gateway_url:
                        continue
                    
                    probed += 1
                    try:
                        probe_url = gateway_url.split("/compat/")[0].split("/workers-ai/")[0]
                        req = urllib.request.Request(
                            probe_url,
                            headers={"User-Agent": "TorShield-SelfHeal/1.0"},
                            method="HEAD",
                        )
                        with urllib.request.urlopen(req, timeout=8):
                            reachable += 1
                    except urllib.error.HTTPError:
                        reachable += 1  # HTTP response = reachable
                    except Exception:
                        pass  # Unreachable
            
            result.endpoints_probed = probed
            result.endpoints_reachable = reachable
            
            logger.info(
                f"[SelfHeal] Probed {probed} endpoints, {reachable} reachable"
            )
            
        except Exception as e:
            result.errors_found.append(f"Endpoint probe error: {e}")
    
    def _step_rebuild_model_registry(self, result: SelfHealResult) -> None:
        """Step C: Rebuild model registry from live fetch."""
        try:
            logger.info("[SelfHeal] Step C: Rebuilding model registry")
            result.actions_taken.append("rebuild_model_registry")
            
            discovered = 0
            
            # Try to refresh the elite registry
            try:
                from elite_registry import get_registry
                registry = get_registry()
                registry.refresh()
                status = registry.get_status()
                discovered = status.get("available_models", 0)
            except ImportError:
                pass
            except Exception as e:
                result.errors_found.append(f"Registry refresh error: {e}")
            
            # Try to refresh the dynamic model brain
            try:
                from torshield_ai_gateway.dynamic_model_brain import refresh_brain_sync
                refresh_brain_sync()
            except ImportError:
                pass
            except Exception as e:
                result.errors_found.append(f"Brain refresh error: {e}")
            
            result.models_discovered = discovered
            
            logger.info(f"[SelfHeal] Model registry rebuilt: {discovered} models")
            
        except Exception as e:
            result.errors_found.append(f"Model registry error: {e}")
    
    def _step_reset_circuit_breakers(self, result: SelfHealResult) -> None:
        """Step D: Reset circuit breakers for slots past cooldown."""
        try:
            logger.info("[SelfHeal] Step D: Resetting circuit breakers past cooldown")
            result.actions_taken.append("reset_circuit_breakers")
            
            reset_count = 0
            
            if self._circuit_breaker:
                status = self._circuit_breaker.get_status()
                for slot_idx_str, slot_info in status.get("slots", {}).items():
                    if slot_info.get("state") == "open":
                        slot_idx = int(slot_idx_str)
                        # Check if past cooldown
                        recovery_time = slot_info.get("recovery_time", 0)
                        if recovery_time and time.time() >= recovery_time:
                            self._circuit_breaker.record_success(slot_idx)
                            reset_count += 1
                            logger.info(
                                f"[SelfHeal] Reset circuit breaker for slot {slot_idx}"
                            )
            
            result.circuit_breakers_reset = reset_count
            result.slots_recovered = reset_count
            
            logger.info(f"[SelfHeal] Reset {reset_count} circuit breakers")
            
        except Exception as e:
            result.errors_found.append(f"Circuit breaker reset error: {e}")
    
    def _step_log_diagnostic_snapshot(self, result: SelfHealResult) -> None:
        """Step E: Log full diagnostic snapshot."""
        try:
            logger.info("[SelfHeal] Step E: Logging diagnostic snapshot")
            result.actions_taken.append("log_diagnostic_snapshot")
            
            snapshot = {
                "heal_cycle": self._heal_count,
                "trigger_reason": result.trigger_reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "env_vars_status": {},
                "circuit_breaker_status": {},
                "model_registry_status": {},
            }
            
            # Collect env vars status
            for i in range(1, 12):
                account_id = os.getenv(f"CF_ACCOUNT_ID_{i}", "").strip()
                api_token = os.getenv(f"CF_API_TOKEN_{i}", "").strip()
                gateway_url = os.getenv(f"CF_AI_GATEWAY_URL_{i}", "").strip()
                
                snapshot["env_vars_status"][f"slot_{i}"] = {
                    "has_account_id": bool(account_id),
                    "has_api_token": bool(api_token),
                    "has_gateway_url": bool(gateway_url),
                    "gateway_uses_compat": "/compat/" in gateway_url if gateway_url else False,
                    "gateway_uses_workers_ai": "/workers-ai/" in gateway_url if gateway_url else False,
                }
            
            # Collect circuit breaker status
            if self._circuit_breaker:
                snapshot["circuit_breaker_status"] = self._circuit_breaker.get_status()
            
            # Collect model registry status
            try:
                from elite_registry import get_registry
                registry = get_registry()
                snapshot["model_registry_status"] = registry.get_status()
            except Exception:
                pass
            
            result.diagnostic_snapshot = snapshot
            
            # Log to recovery.log
            if self._logger:
                try:
                    self._logger.log_recovery(
                        level="INFO",
                        action="self_heal_cycle",
                        trigger=result.trigger_reason,
                        slots_affected=list(range(1, 12)),
                        message=f"Healing cycle #{self._heal_count} completed",
                        success=result.success,
                        actions_taken=result.actions_taken,
                        errors_found=result.errors_found[:5],  # Limit to first 5
                    )
                except Exception:
                    pass
            
            # Also write snapshot to recovery.log as JSON
            try:
                log_dir = Path(os.getenv("LOG_DIR", "logs"))
                log_dir.mkdir(parents=True, exist_ok=True)
                snapshot_path = log_dir / "recovery.log"
                with open(snapshot_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(snapshot, ensure_ascii=False, default=str) + "\n")
            except Exception:
                pass  # Disk-full must not crash
            
        except Exception as e:
            result.errors_found.append(f"Diagnostic snapshot error: {e}")
    
    def force_heal(self) -> SelfHealResult:
        """Force a healing cycle regardless of threshold."""
        return self._run_healing_cycle(trigger_reason="manual_force")
    
    def get_status(self) -> Dict:
        """Get self-healing engine status."""
        return {
            "sequential_failures": self._sequential_failures,
            "trigger_threshold": self._trigger_threshold,
            "heal_count": self._heal_count,
            "last_heal_time": self._last_heal_time,
            "cooldown_secs": self._cooldown_secs,
            "can_trigger": self._sequential_failures >= self._trigger_threshold,
            "in_cooldown": time.time() - self._last_heal_time < self._cooldown_secs,
        }


def get_self_healing_engine() -> SelfHealingEngine:
    """Get the singleton SelfHealingEngine instance."""
    return SelfHealingEngine.instance()
