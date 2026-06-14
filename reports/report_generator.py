#!/usr/bin/env python3
"""
report_generator.py — JSON Report Generator v1.0
═══════════════════════════════════════════════════════════════════════════════

Auto-generates three JSON reports on completion:
  1. diagnostics_report.json: Failures, root causes, slot health
  2. repair_report.json: Actions taken, models rotated, slots recovered
  3. health_report.json: Per-provider status, latency, success rate

DESIGN PRINCIPLES:
  - ADDITIVE ONLY: Does not modify existing code
  - ZERO CRASH: All operations wrapped in try/except
  - Feature-flagged: ENABLE_REPORT_GENERATION=true
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("torshield.reports")


class ReportGenerator:
    """Auto-generates diagnostic, repair, and health reports."""
    
    _instance: Optional["ReportGenerator"] = None
    _instance_lock = None  # Will be set in __init__
    
    def __init__(self, output_dir: str = "reports"):
        import threading
        self._lock = threading.Lock()
        self._output_dir = Path(output_dir)
        self._repair_actions: List[Dict] = []
        self._diagnostic_events: List[Dict] = []
        self._provider_health: Dict[str, Dict] = {}
        self._start_time = time.time()
        
        try:
            self._output_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            self._output_dir = Path(".")
    
    @classmethod
    def instance(cls, output_dir: str = "reports") -> "ReportGenerator":
        if cls._instance is None:
            cls._instance = cls(output_dir)
        return cls._instance
    
    def record_diagnostic_event(
        self,
        event_type: str,
        provider: str = "",
        slot: int = 0,
        model: str = "",
        error_code: str = "",
        root_cause: str = "",
        details: Dict = None,
    ) -> None:
        """Record a diagnostic event for the diagnostics report."""
        try:
            self._diagnostic_events.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "provider": provider,
                "slot": slot,
                "model": model,
                "error_code": error_code,
                "root_cause": root_cause,
                "details": details or {},
            })
        except Exception:
            pass
    
    def record_repair_action(
        self,
        action: str,
        target: str = "",
        old_value: str = "",
        new_value: str = "",
        success: bool = True,
        details: Dict = None,
    ) -> None:
        """Record a repair action for the repair report."""
        try:
            self._repair_actions.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": action,
                "target": target,
                "old_value": old_value,
                "new_value": new_value,
                "success": success,
                "details": details or {},
            })
        except Exception:
            pass
    
    def update_provider_health(
        self,
        provider: str,
        status: str = "unknown",
        latency_ms: float = 0.0,
        success_rate: float = 0.0,
        total_requests: int = 0,
        total_failures: int = 0,
        available_slots: int = 0,
        error_codes: List[str] = None,
    ) -> None:
        """Update provider health information."""
        try:
            self._provider_health[provider] = {
                "status": status,
                "latency_ms": round(latency_ms, 1),
                "success_rate": round(success_rate, 3),
                "total_requests": total_requests,
                "total_failures": total_failures,
                "available_slots": available_slots,
                "error_codes": error_codes or [],
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }
        except Exception:
            pass
    
    def generate_diagnostics_report(self) -> Dict:
        """Generate diagnostics_report.json — failures, root causes, slot health."""
        try:
            # Collect slot health from circuit breaker (lazy, fail-safe)
            slot_health = {}
            try:
                if hasattr(self, '_cb_status_cache') and self._cb_status_cache:
                    slot_health = self._cb_status_cache
            except Exception:
                pass
            
            # Collect endpoint validation results
            endpoint_results = {}
            try:
                from core.endpoint_validator import get_validator
                validator = get_validator()
                summary = validator.get_validation_summary()
                endpoint_results = summary.get("results", {})
            except Exception:
                pass
            
            report = {
                "report_type": "diagnostics",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "uptime_seconds": round(time.time() - self._start_time, 1),
                "total_diagnostic_events": len(self._diagnostic_events),
                "events": self._diagnostic_events[-100:],  # Last 100 events
                "slot_health": slot_health,
                "endpoint_validation": endpoint_results,
                "root_cause_analysis": self._analyze_root_causes(),
            }
            
            self._write_report("diagnostics_report.json", report)
            return report
        except Exception as e:
            logger.error(f"[Reports] Diagnostics report error: {e}")
            return {"error": str(e)}
    
    def generate_repair_report(self) -> Dict:
        """Generate repair_report.json — actions taken, models rotated, slots recovered."""
        try:
            # Categorize repair actions
            actions_by_type = {}
            for action in self._repair_actions:
                action_type = action.get("action", "unknown")
                if action_type not in actions_by_type:
                    actions_by_type[action_type] = []
                actions_by_type[action_type].append(action)
            
            # Count models rotated
            models_rotated = [
                a for a in self._repair_actions
                if a.get("action") == "model_rotation"
            ]
            
            # Count slots recovered
            slots_recovered = [
                a for a in self._repair_actions
                if a.get("action") in ("circuit_breaker_reset", "slot_recovery")
            ]
            
            # Count URL path fixes
            url_fixes = [
                a for a in self._repair_actions
                if a.get("action") == "endpoint_path_fix"
            ]
            
            report = {
                "report_type": "repair",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_actions": len(self._repair_actions),
                "models_rotated": len(models_rotated),
                "slots_recovered": len(slots_recovered),
                "endpoint_path_fixes": len(url_fixes),
                "actions_by_type": {
                    k: len(v) for k, v in actions_by_type.items()
                },
                "actions": self._repair_actions[-100:],
                "critical_fix": {
                    "description": "CF AI Gateway /workers-ai/ → /compat/ path fix",
                    "affected_slots": [a.get("target", "") for a in url_fixes],
                    "fix_applied": len(url_fixes) > 0,
                    "old_path": "/workers-ai/v1/chat/completions",
                    "new_path": "/compat/chat/completions",
                },
            }
            
            self._write_report("repair_report.json", report)
            return report
        except Exception as e:
            logger.error(f"[Reports] Repair report error: {e}")
            return {"error": str(e)}
    
    def generate_health_report(self) -> Dict:
        """Generate health_report.json — per-provider status, latency, success rate."""
        try:
            # Collect provider health (lazy, fail-safe)
            try:
                if hasattr(self, '_gw_health_cache') and self._gw_health_cache:
                    self._provider_health.update(self._gw_health_cache)
            except Exception:
                pass
            
            # Calculate overall health
            healthy_providers = sum(
                1 for p in self._provider_health.values()
                if p.get("status") in ("healthy", "ok")
            )
            total_providers = len(self._provider_health) or 1
            
            report = {
                "report_type": "health",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "overall_status": "healthy" if healthy_providers >= 2 else "degraded",
                "healthy_provider_count": healthy_providers,
                "total_provider_count": total_providers,
                "provider_details": self._provider_health,
                "uptime_seconds": round(time.time() - self._start_time, 1),
            }
            
            self._write_report("health_report.json", report)
            return report
        except Exception as e:
            logger.error(f"[Reports] Health report error: {e}")
            return {"error": str(e)}
    
    def generate_all_reports(self) -> Dict[str, Dict]:
        """Generate all three reports at once."""
        return {
            "diagnostics": self.generate_diagnostics_report(),
            "repair": self.generate_repair_report(),
            "health": self.generate_health_report(),
        }
    
    def _analyze_root_causes(self) -> List[Dict]:
        """Analyze diagnostic events to identify root causes."""
        root_causes = []
        
        try:
            # Group events by error_code
            error_counts = {}
            for event in self._diagnostic_events:
                error_code = event.get("error_code", "unknown")
                if error_code not in error_counts:
                    error_counts[error_code] = 0
                error_counts[error_code] += 1
            
            # Identify dominant error patterns
            for error_code, count in sorted(
                error_counts.items(), key=lambda x: x[1], reverse=True
            ):
                if count > 0:
                    root_cause = {
                        "error_code": error_code,
                        "count": count,
                        "percentage": round(count / max(len(self._diagnostic_events), 1) * 100, 1),
                    }
                    
                    # Add known root cause mappings
                    if error_code == "HTTP 400" or "400" in str(error_code):
                        root_cause["root_cause"] = "CF AI Gateway /workers-ai/ endpoint path causes HTTP 400"
                        root_cause["fix"] = "Use /compat/chat/completions instead of /workers-ai/v1/chat/completions"
                    elif error_code == "HTTP 429" or "429" in str(error_code):
                        root_cause["root_cause"] = "Rate limiting from provider"
                        root_cause["fix"] = "Exponential backoff with jitter, rotate to next slot"
                    elif error_code == "HTTP 403" or "403" in str(error_code):
                        root_cause["root_cause"] = "Authentication failure or bot detection"
                        root_cause["fix"] = "Check API key validity, rotate to next slot"
                    elif "timeout" in str(error_code).lower():
                        root_cause["root_cause"] = "Network timeout"
                        root_cause["fix"] = "Rotate to next slot immediately"
                    else:
                        root_cause["root_cause"] = "Unknown"
                        root_cause["fix"] = "Investigate and add to error catalog"
                    
                    root_causes.append(root_cause)
        except Exception:
            pass
        
        return root_causes
    
    def _write_report(self, filename: str, data: Dict) -> None:
        """Write report to JSON file. FAIL-SAFE: catches all I/O errors."""
        try:
            path = self._output_dir / filename
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            logger.info(f"[Reports] Written {filename}")
        except Exception as e:
            logger.error(f"[Reports] Failed to write {filename}: {e}")


def get_report_generator(output_dir: str = "reports") -> ReportGenerator:
    """Get the singleton ReportGenerator instance."""
    return ReportGenerator.instance(output_dir)
