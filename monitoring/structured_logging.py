"""
monitoring.structured_logging — Structured JSON logging, observability, and analytics.

Provides:
  1. StructuredJsonFormatter — JSON log formatter with timestamp, level, module,
     function, message, and extra_fields.
  2. ProviderHealthMetrics  — Per-provider metrics: request count, success count,
     failure count, avg latency, last error, circuit state.
  3. PerformanceReport       — Generate a JSON performance report with provider
     stats, gateway stats, and model selector stats.
  4. FailureAnalytics        — Classify failures by type (auth, network, model,
     quota) and generate a breakdown report.
  5. HealthReportGenerator   — Combine all metrics into a comprehensive health
     report JSON.

Usage:
    from monitoring.structured_logging import (
        StructuredJsonFormatter,
        ProviderHealthMetrics,
        PerformanceReport,
        FailureAnalytics,
        HealthReportGenerator,
    )

    # Setup structured logging
    import logging
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredJsonFormatter())
    logging.root.addHandler(handler)

    # Track provider health
    metrics = ProviderHealthMetrics()
    metrics.record_request("cerebras", success=True, latency_ms=120.5)
    metrics.record_request("cerebras", success=False, latency_ms=0,
                           error="401 Unauthorized", failure_type="auth")

    # Generate reports
    report = HealthReportGenerator(metrics=metrics)
    report.generate()
    report.save("data/observability_report.json")
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is on sys.path for lazy imports
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Structured JSON Logging
# ══════════════════════════════════════════════════════════════════════════════

class StructuredJsonFormatter(logging.Formatter):
    """
    Format log records as JSON with structured fields.

    Output fields:
        timestamp    — ISO-8601 UTC timestamp
        level        — Log level name (INFO, WARNING, ERROR, etc.)
        module       — Module name that emitted the record
        function     — Function name that emitted the record
        message      — Formatted log message
        extra_fields — Any extra fields passed via logging calls
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "module": record.module,
            "function": record.funcName,
            "message": record.getMessage(),
            "extra_fields": {},
        }

        # Extract extra fields — anything not in the standard LogRecord attributes
        standard_attrs = {
            "name", "msg", "args", "created", "relativeCreated",
            "exc_info", "exc_text", "stack_info", "lineno", "funcName",
            "pathname", "filename", "module", "levelno", "levelname",
            "thread", "threadName", "process", "processName", "message",
            "msecs", "taskName",
        }
        for key, value in record.__dict__.items():
            if key not in standard_attrs and not key.startswith("_"):
                log_entry["extra_fields"][key] = value

        # Include exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["extra_fields"]["exception_type"] = record.exc_info[0].__name__
            log_entry["extra_fields"]["exception_message"] = str(record.exc_info[1])
            log_entry["extra_fields"]["traceback"] = traceback.format_exception(
                *record.exc_info
            )

        return json.dumps(log_entry, ensure_ascii=False, default=str)


def setup_structured_logging(
    level: int = logging.INFO,
    logger_name: Optional[str] = None,
) -> logging.Logger:
    """
    Configure structured JSON logging on a logger.

    Args:
        level:       Logging level (default INFO).
        logger_name: Specific logger to configure. None = root logger.

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(level)

    # Avoid adding duplicate handlers
    if not any(isinstance(h.formatter, StructuredJsonFormatter) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(StructuredJsonFormatter())
        logger.addHandler(handler)

    return logger


# ══════════════════════════════════════════════════════════════════════════════
# 2. Provider Health Metrics
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ProviderMetrics:
    """Per-provider health metrics."""
    name: str
    request_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    total_latency_ms: float = 0.0
    last_error: Optional[str] = None
    last_error_time: Optional[str] = None
    circuit_state: str = "closed"  # closed, open, half_open

    @property
    def avg_latency_ms(self) -> float:
        if self.success_count == 0:
            return 0.0
        return self.total_latency_ms / self.success_count

    @property
    def success_rate(self) -> float:
        if self.request_count == 0:
            return 0.0
        return self.success_count / self.request_count


class ProviderHealthMetrics:
    """
    Track per-provider health metrics including request counts,
    success/failure rates, average latency, last error, and circuit state.
    """

    KNOWN_PROVIDERS = [
        "cerebras",
        "cloudflare_ai_gateway",
        "cloudflare_workers_ai",
        "portkey",
    ]

    def __init__(self):
        self._providers: Dict[str, ProviderMetrics] = {}
        for name in self.KNOWN_PROVIDERS:
            self._providers[name] = ProviderMetrics(name=name)

    def _get_or_create(self, provider_name: str) -> ProviderMetrics:
        if provider_name not in self._providers:
            self._providers[provider_name] = ProviderMetrics(name=provider_name)
        return self._providers[provider_name]

    def record_request(
        self,
        provider_name: str,
        success: bool,
        latency_ms: float = 0.0,
        error: Optional[str] = None,
        failure_type: Optional[str] = None,
    ) -> None:
        """
        Record a provider request result.

        Args:
            provider_name: Name of the provider.
            success:       Whether the request succeeded.
            latency_ms:    Request latency in milliseconds.
            error:         Error message if the request failed.
            failure_type:  Category of failure (auth, network, model, quota).
        """
        metrics = self._get_or_create(provider_name)
        metrics.request_count += 1

        if success:
            metrics.success_count += 1
            metrics.total_latency_ms += latency_ms
        else:
            metrics.failure_count += 1
            metrics.last_error = error or "unknown"
            metrics.last_error_time = datetime.now(timezone.utc).isoformat()

    def update_circuit_state(self, provider_name: str, state: str) -> None:
        """Update the circuit breaker state for a provider."""
        metrics = self._get_or_create(provider_name)
        valid_states = {"closed", "open", "half_open"}
        metrics.circuit_state = state if state in valid_states else "unknown"

    def get_provider_metrics(self, provider_name: str) -> Optional[ProviderMetrics]:
        """Get metrics for a specific provider."""
        return self._providers.get(provider_name)

    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get metrics for all providers as dictionaries."""
        return {name: asdict(m) for name, m in self._providers.items()}

    def refresh_from_gateway(self) -> None:
        """Refresh metrics from the live gateway instance if available."""
        try:
            from torshield_ai_gateway.gateway import get_gateway
            gateway = get_gateway()
            stats = gateway.health_stats()

            for name in self.KNOWN_PROVIDERS:
                provider = gateway._providers.get(name)
                if provider and hasattr(provider, "_circuit_breaker"):
                    self.update_circuit_state(name, provider._circuit_breaker.state)
                elif name in self._providers:
                    self.update_circuit_state(name, "unknown")

            # Update request counts from gateway stats
            provider_attempts = stats.get("provider_attempts", {})
            for name, count in provider_attempts.items():
                metrics = self._get_or_create(name)
                # Only update if gateway has more recent data
                if count > metrics.request_count:
                    metrics.request_count = count

        except Exception as e:
            logging.getLogger("torshield.monitoring").debug(
                f"Could not refresh from gateway: {e}"
            )


# ══════════════════════════════════════════════════════════════════════════════
# 3. Performance Reports
# ══════════════════════════════════════════════════════════════════════════════

class PerformanceReport:
    """
    Generate a JSON performance report combining:
      - Provider health metrics
      - Gateway stats
      - Model selector stats
    """

    def __init__(self, metrics: Optional[ProviderHealthMetrics] = None):
        self._metrics = metrics or ProviderHealthMetrics()

    def _get_gateway_stats(self) -> Dict[str, Any]:
        """Fetch current gateway health statistics."""
        try:
            from torshield_ai_gateway.gateway import get_gateway
            gateway = get_gateway()
            return gateway.health_stats()
        except Exception as e:
            logging.getLogger("torshield.monitoring").debug(
                f"Could not fetch gateway stats: {e}"
            )
            return {}

    def _get_model_selector_stats(self) -> Dict[str, Any]:
        """Fetch model selector status."""
        try:
            from torshield_ai_gateway.model_selector import model_selector_status
            return model_selector_status()
        except Exception as e:
            logging.getLogger("torshield.monitoring").debug(
                f"Could not fetch model selector stats: {e}"
            )
            return {}

    def generate(self) -> Dict[str, Any]:
        """
        Generate a comprehensive performance report.

        Returns:
            Dictionary with provider_stats, gateway_stats, model_selector_stats.
        """
        self._metrics.refresh_from_gateway()

        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "provider_stats": self._metrics.get_all_metrics(),
            "gateway_stats": self._get_gateway_stats(),
            "model_selector_stats": self._get_model_selector_stats(),
        }

        # Add summary
        provider_stats = report["provider_stats"]
        total_requests = sum(
            p.get("request_count", 0) for p in provider_stats.values()
        )
        total_successes = sum(
            p.get("success_count", 0) for p in provider_stats.values()
        )
        total_failures = sum(
            p.get("failure_count", 0) for p in provider_stats.values()
        )

        report["summary"] = {
            "total_provider_requests": total_requests,
            "total_provider_successes": total_successes,
            "total_provider_failures": total_failures,
            "overall_success_rate": (
                total_successes / total_requests if total_requests > 0 else 0.0
            ),
            "healthy_providers": sum(
                1 for p in provider_stats.values()
                if p.get("circuit_state") == "closed"
            ),
            "degraded_providers": sum(
                1 for p in provider_stats.values()
                if p.get("circuit_state") in ("open", "half_open")
            ),
        }

        return report

    def save(self, path: Optional[str] = None) -> str:
        """
        Save the performance report to a JSON file.

        Args:
            path: Output file path. Defaults to data/performance_report.json.

        Returns:
            Path to the saved report.
        """
        output_path = Path(path) if path else Path("data/performance_report.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        report = self.generate()
        output_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        return str(output_path)


# ══════════════════════════════════════════════════════════════════════════════
# 4. Failure Analytics
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class FailureRecord:
    """A single failure event record."""
    timestamp: str
    provider: str
    failure_type: str  # auth, network, model, quota, unknown
    error_message: str
    http_status: Optional[int] = None
    is_retryable: bool = False


class FailureAnalytics:
    """
    Classify and analyze failures by type.

    Failure categories:
        auth     — Authentication errors (401, 403, invalid key)
        network  — Network/connectivity errors (timeout, DNS, connection refused)
        model    — Model errors (404, invalid model, wrong response)
        quota    — Rate limiting / quota errors (429, quota exceeded)
        unknown  — Unclassified failures
    """

    # Classification rules based on HTTP status codes
    STATUS_MAP = {
        400: "model",     # Bad Request (often invalid model)
        401: "auth",      # Unauthorized
        403: "auth",      # Forbidden
        404: "model",     # Not Found (model not found)
        429: "quota",     # Rate Limited
        500: "network",   # Internal Server Error (transient)
        502: "network",   # Bad Gateway
        503: "network",   # Service Unavailable
        504: "network",   # Gateway Timeout
    }

    # Classification rules based on error message keywords
    KEYWORD_MAP = {
        "auth": [
            "unauthorized", "forbidden", "invalid key", "invalid api key",
            "authentication", "auth", "401", "403", "access denied",
        ],
        "network": [
            "timeout", "connection", "dns", "refused", "network", "unreachable",
            "ssl", "tls", "certifi", "resolve", "reset", "broken pipe",
            "502", "503", "504",
        ],
        "model": [
            "model not found", "invalid model", "no route", "wrong response",
            "400", "404", "unsupported model",
        ],
        "quota": [
            "rate limit", "quota", "too many requests", "429",
            "exceeded", "throttl",
        ],
    }

    def __init__(self):
        self._failures: List[FailureRecord] = []
        self._max_failures = 1000

    def classify_failure(
        self, error_message: str, http_status: Optional[int] = None
    ) -> str:
        """
        Classify a failure into a category.

        Args:
            error_message: The error message string.
            http_status:   Optional HTTP status code.

        Returns:
            Failure category: "auth", "network", "model", "quota", or "unknown".
        """
        # Try HTTP status code first (most reliable)
        if http_status and http_status in self.STATUS_MAP:
            return self.STATUS_MAP[http_status]

        # Fall back to keyword matching
        message_lower = error_message.lower()
        for category, keywords in self.KEYWORD_MAP.items():
            for keyword in keywords:
                if keyword in message_lower:
                    return category

        return "unknown"

    def is_retryable(self, failure_type: str) -> bool:
        """Determine if a failure type is retryable (transient)."""
        return failure_type in ("network", "quota")

    def record_failure(
        self,
        provider: str,
        error_message: str,
        http_status: Optional[int] = None,
    ) -> str:
        """
        Record and classify a failure event.

        Args:
            provider:      Provider name.
            error_message: Error message.
            http_status:   Optional HTTP status code.

        Returns:
            The classified failure type.
        """
        failure_type = self.classify_failure(error_message, http_status)

        record = FailureRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            provider=provider,
            failure_type=failure_type,
            error_message=error_message[:500],  # Truncate long messages
            http_status=http_status,
            is_retryable=self.is_retryable(failure_type),
        )

        self._failures.append(record)
        if len(self._failures) > self._max_failures:
            self._failures = self._failures[-self._max_failures:]

        return failure_type

    def get_breakdown(self) -> Dict[str, Any]:
        """
        Generate a failure breakdown report.

        Returns:
            Dictionary with failure counts by type, provider, and retryability.
        """
        by_type: Dict[str, int] = {}
        by_provider: Dict[str, int] = {}
        retryable_count = 0
        non_retryable_count = 0

        for f in self._failures:
            by_type[f.failure_type] = by_type.get(f.failure_type, 0) + 1
            by_provider[f.provider] = by_provider.get(f.provider, 0) + 1
            if f.is_retryable:
                retryable_count += 1
            else:
                non_retryable_count += 1

        # Recent failures (last 10)
        recent = [
            {
                "timestamp": f.timestamp,
                "provider": f.provider,
                "type": f.failure_type,
                "error": f.error_message[:200],
                "http_status": f.http_status,
                "retryable": f.is_retryable,
            }
            for f in self._failures[-10:]
        ]

        return {
            "total_failures": len(self._failures),
            "by_type": by_type,
            "by_provider": by_provider,
            "retryable": retryable_count,
            "non_retryable": non_retryable_count,
            "recent_failures": recent,
        }

    def get_failures(self) -> List[FailureRecord]:
        """Return all recorded failure records."""
        return list(self._failures)

    def clear(self) -> None:
        """Clear all recorded failures."""
        self._failures.clear()


# ══════════════════════════════════════════════════════════════════════════════
# 5. Health Report Generator
# ══════════════════════════════════════════════════════════════════════════════

class HealthReportGenerator:
    """
    Combine all metrics into a comprehensive health report JSON.

    The report includes:
      - System metadata (timestamp, run_id, version)
      - Provider health metrics
      - Gateway stats
      - Model selector stats
      - Failure analytics breakdown
      - Performance summary
      - Overall health status
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        metrics: Optional[ProviderHealthMetrics] = None,
        analytics: Optional[FailureAnalytics] = None,
    ):
        self._metrics = metrics or ProviderHealthMetrics()
        self._analytics = analytics or FailureAnalytics()
        self._perf_report = PerformanceReport(metrics=self._metrics)

    def _determine_overall_status(self, report: Dict[str, Any]) -> str:
        """
        Determine overall system health status.

        Returns:
            "healthy", "degraded", or "critical"
        """
        provider_stats = report.get("provider_stats", {})
        gateway_stats = report.get("gateway_stats", {})
        failure_breakdown = report.get("failure_analytics", {}).get("by_type", {})

        # Count providers by circuit state
        open_count = sum(
            1 for p in provider_stats.values()
            if p.get("circuit_state") == "open"
        )
        total_providers = len(provider_stats) or 1

        # Check degraded rate from gateway
        degraded_rate = gateway_stats.get("degraded_rate", 0.0)

        # Check for high auth failure rate
        auth_failures = failure_breakdown.get("auth", 0)
        total_failures = sum(failure_breakdown.values()) or 1
        auth_rate = auth_failures / total_failures

        # Determine status
        if open_count == total_providers and total_providers > 0:
            return "critical"
        if degraded_rate > 0.5:
            return "critical"
        if auth_rate > 0.5 and total_failures > 3:
            return "critical"
        if open_count > 0 or degraded_rate > 0.2:
            return "degraded"
        return "healthy"

    def generate(self) -> Dict[str, Any]:
        """
        Generate a comprehensive health report.

        Returns:
            Dictionary with complete system health status.
        """
        # Refresh metrics from gateway
        self._metrics.refresh_from_gateway()

        # Collect all sub-reports
        performance = self._perf_report.generate()
        failure_breakdown = self._analytics.get_breakdown()

        report = {
            "version": self.VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
            "system": {
                "python_version": sys.version.split()[0],
                "platform": sys.platform,
            },
            "provider_stats": performance.get("provider_stats", {}),
            "gateway_stats": performance.get("gateway_stats", {}),
            "model_selector_stats": performance.get("model_selector_stats", {}),
            "performance_summary": performance.get("summary", {}),
            "failure_analytics": failure_breakdown,
        }

        # Determine overall status
        report["overall_status"] = self._determine_overall_status(report)

        # Add recommendations
        report["recommendations"] = self._generate_recommendations(report)

        return report

    def _generate_recommendations(self, report: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on the health report."""
        recommendations = []
        provider_stats = report.get("provider_stats", {})
        failure_analytics = report.get("failure_analytics", {})

        # Check for open circuits
        for name, stats in provider_stats.items():
            if stats.get("circuit_state") == "open":
                recommendations.append(
                    f"Provider '{name}' circuit breaker is OPEN — "
                    f"check provider health and credentials"
                )

        # Check for auth failures
        by_type = failure_analytics.get("by_type", {})
        if by_type.get("auth", 0) > 0:
            recommendations.append(
                f"Authentication failures detected ({by_type['auth']} events) — "
                f"verify API keys and tokens"
            )

        # Check for network failures
        if by_type.get("network", 0) > 2:
            recommendations.append(
                f"Repeated network failures ({by_type['network']} events) — "
                f"check connectivity and DNS resolution"
            )

        # Check for quota issues
        if by_type.get("quota", 0) > 0:
            recommendations.append(
                f"Rate limiting detected ({by_type['quota']} events) — "
                f"consider reducing request rate or rotating keys"
            )

        # Check degraded rate
        degraded_rate = report.get("gateway_stats", {}).get("degraded_rate", 0.0)
        if degraded_rate > 0.2:
            recommendations.append(
                f"High LocalAIEngine fallback rate ({degraded_rate:.1%}) — "
                f"primary providers may be unavailable"
            )

        if not recommendations:
            recommendations.append("All systems operating normally — no action required")

        return recommendations

    def save(self, path: Optional[str] = None) -> str:
        """
        Save the comprehensive health report to a JSON file.

        Args:
            path: Output file path. Defaults to data/observability_report.json.

        Returns:
            Path to the saved report.
        """
        output_path = Path(path) if path else Path("data/observability_report.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        report = self.generate()
        output_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        return str(output_path)

    def print_summary(self) -> None:
        """Print a human-readable summary of the health report."""
        report = self.generate()

        print("\n" + "=" * 72)
        print(f"  TorShield Observability Report — {report['timestamp']}")
        print(f"  Version: {report['version']}  |  Status: {report['overall_status'].upper()}")
        print("=" * 72)

        # Provider stats
        print("\n  Provider Health:")
        for name, stats in report.get("provider_stats", {}).items():
            circuit = stats.get("circuit_state", "unknown")
            icon = "🟢" if circuit == "closed" else "🔴" if circuit == "open" else "🟡"
            req = stats.get("request_count", 0)
            lat = stats.get("avg_latency_ms", 0)
            print(f"    {icon} {name:<28} circuit={circuit:<10} reqs={req}  lat={lat:.0f}ms")

        # Gateway stats
        gw = report.get("gateway_stats", {})
        if gw:
            print(f"\n  Gateway:")
            print(f"    Total requests:  {gw.get('total_requests', 0)}")
            print(f"    Primary success: {gw.get('primary_success_rate', 0):.1%}")
            print(f"    Degraded rate:   {gw.get('degraded_rate', 0):.1%}")

        # Failure analytics
        fa = report.get("failure_analytics", {})
        if fa and fa.get("total_failures", 0) > 0:
            print(f"\n  Failure Analytics:")
            for ftype, count in fa.get("by_type", {}).items():
                print(f"    {ftype}: {count}")
            print(f"    Retryable: {fa.get('retryable', 0)}  Non-retryable: {fa.get('non_retryable', 0)}")

        # Recommendations
        print(f"\n  Recommendations:")
        for rec in report.get("recommendations", []):
            print(f"    → {rec}")

        print("=" * 72 + "\n")


# ══════════════════════════════════════════════════════════════════════════════
# CLI entry point
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    """Generate and save a comprehensive observability report."""
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s — %(message)s",
    )

    metrics = ProviderHealthMetrics()
    analytics = FailureAnalytics()
    generator = HealthReportGenerator(metrics=metrics, analytics=analytics)

    # Print summary to stdout
    generator.print_summary()

    # Save full report
    report_path = generator.save()
    print(f"Full report saved to: {report_path}")


if __name__ == "__main__":
    main()
