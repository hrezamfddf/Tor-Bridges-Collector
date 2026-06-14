#!/usr/bin/env python3
"""
structured_logger.py — Structured JSON Logging System v1.0
═══════════════════════════════════════════════════════════════════════════════

Fail-safe structured logging to multiple log files.
Format: JSON lines with timestamp, level, provider, slot, model, error_code.
ALL log writes wrapped in try/except — disk-full must not crash service.

Log Files:
  - diagnostics.log: Startup validation, slot health, endpoint probes
  - monitor.log: DPI events, slot poisoning, self-heal events
  - recovery.log: Self-healing diagnostics, recovery actions
  - gateway.log: Request routing, provider selection, latency tracking

DESIGN PRINCIPLES:
  - ADDITIVE ONLY: Does not modify existing logging
  - ZERO CRASH: All I/O wrapped in try/except
  - FAIL-SAFE: Disk-full or permission errors never crash the service
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("torshield.structured_logger")


class StructuredLogger:
    """
    Fail-safe structured JSON logger.
    
    Writes JSON lines to multiple log files with automatic rotation.
    ALL write operations are wrapped in try/except to prevent crashes.
    """

    _instance: Optional["StructuredLogger"] = None
    _instance_lock = threading.Lock()

    def __init__(self, log_dir: str = "logs"):
        self._lock = threading.Lock()
        self._log_dir = Path(log_dir)
        self._max_bytes = int(os.getenv("LOG_MAX_MB", "10")) * 1024 * 1024
        
        # Ensure log directory exists
        try:
            self._log_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            self._log_dir = Path(".")
        
        # Log file handles
        self._files = {
            "diagnostics": self._log_dir / "diagnostics.log",
            "monitor": self._log_dir / "monitor.log",
            "recovery": self._log_dir / "recovery.log",
            "gateway": self._log_dir / "gateway.log",
        }

    @classmethod
    def instance(cls, log_dir: str = "logs") -> "StructuredLogger":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls(log_dir)
        return cls._instance

    def _write_log(self, log_type: str, entry: Dict[str, Any]) -> None:
        """
        Write a JSON line to the specified log file.
        FAIL-SAFE: Catches ALL exceptions including disk-full.
        """
        try:
            entry["timestamp"] = datetime.now(timezone.utc).isoformat()
            entry["log_type"] = log_type
            
            log_path = self._files.get(log_type)
            if not log_path:
                return
            
            # Check file size for rotation
            try:
                if log_path.exists() and log_path.stat().st_size > self._max_bytes:
                    self._rotate_log(log_path)
            except Exception:
                pass  # Rotation failure should not block logging
            
            # Write JSON line
            line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"
            with self._lock:
                try:
                    with open(log_path, "a", encoding="utf-8") as f:
                        f.write(line)
                except (OSError, PermissionError):
                    pass  # Disk-full or permission denied — NEVER crash
                    
        except Exception:
            pass  # Ultimate fail-safe

    def _rotate_log(self, log_path: Path) -> None:
        """Rotate log file when it exceeds max size."""
        try:
            backup = log_path.with_suffix(".log.1")
            if backup.exists():
                backup.unlink()
            log_path.rename(backup)
        except Exception:
            pass

    def log_diagnostics(
        self,
        level: str,
        provider: str = "",
        slot: int = 0,
        model: str = "",
        error_code: str = "",
        message: str = "",
        **kwargs,
    ) -> None:
        """Log a diagnostics entry."""
        self._write_log("diagnostics", {
            "level": level,
            "provider": provider,
            "slot": slot,
            "model": model,
            "error_code": error_code,
            "message": message,
            **kwargs,
        })

    def log_monitor(
        self,
        level: str,
        event_type: str = "",
        provider: str = "",
        slot: int = 0,
        model: str = "",
        error_code: str = "",
        message: str = "",
        **kwargs,
    ) -> None:
        """Log a monitor entry (DPI events, slot poisoning)."""
        self._write_log("monitor", {
            "level": level,
            "event_type": event_type,
            "provider": provider,
            "slot": slot,
            "model": model,
            "error_code": error_code,
            "message": message,
            **kwargs,
        })

    def log_recovery(
        self,
        level: str,
        action: str = "",
        trigger: str = "",
        slots_affected: list = None,
        models_rotated: list = None,
        message: str = "",
        **kwargs,
    ) -> None:
        """Log a recovery/self-healing entry."""
        self._write_log("recovery", {
            "level": level,
            "action": action,
            "trigger": trigger,
            "slots_affected": slots_affected or [],
            "models_rotated": models_rotated or [],
            "message": message,
            **kwargs,
        })

    def log_gateway(
        self,
        level: str,
        provider: str = "",
        slot: int = 0,
        model: str = "",
        latency_ms: float = 0.0,
        success: bool = True,
        error_code: str = "",
        message: str = "",
        **kwargs,
    ) -> None:
        """Log a gateway routing entry."""
        self._write_log("gateway", {
            "level": level,
            "provider": provider,
            "slot": slot,
            "model": model,
            "latency_ms": round(latency_ms, 1),
            "success": success,
            "error_code": error_code,
            "message": message,
            **kwargs,
        })


def get_structured_logger(log_dir: str = "logs") -> StructuredLogger:
    """Get the singleton StructuredLogger instance."""
    return StructuredLogger.instance(log_dir)
