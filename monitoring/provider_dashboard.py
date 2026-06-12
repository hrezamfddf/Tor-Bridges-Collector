"""
monitoring.provider_dashboard — Provider Health Dashboard

Provides a real-time summary dashboard for monitoring AI provider
health, circuit breaker states, latency metrics, and failure rates.
Uses the TorShieldAIGateway health_stats() method as its data source.

Usage:
    from monitoring.provider_dashboard import ProviderHealthDashboard
    dashboard = ProviderHealthDashboard()
    report = dashboard.generate_report()
    dashboard.print_dashboard()
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("torshield.monitoring.dashboard")

DATA_DIR = Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class ProviderHealthSnapshot:
    """A point-in-time health snapshot for a single provider."""
    name: str
    available: bool = False
    circuit_state: str = "unknown"  # closed, open, half_open
    total_requests: int = 0
    successes: int = 0
    failures: int = 0
    avg_latency_ms: float = 0.0
    success_rate: float = 0.0
    last_checked: str = ""

    @property
    def health_icon(self) -> str:
        """Return a visual indicator for the provider health."""
        if not self.available:
            return "⏹"
        if self.circuit_state == "open":
            return "🔴"
        if self.circuit_state == "half_open":
            return "🟡"
        if self.success_rate >= 0.9:
            return "🟢"
        if self.success_rate >= 0.5:
            return "🟡"
        return "🔴"


@dataclass
class DashboardReport:
    """Complete dashboard report with all provider snapshots."""
    timestamp: str = ""
    total_requests: int = 0
    primary_successes: int = 0
    local_fallback_uses: int = 0
    all_primary_failed: int = 0
    primary_success_rate: float = 0.0
    degraded_rate: float = 0.0
    providers: List[ProviderHealthSnapshot] = field(default_factory=list)
    overall_status: str = "unknown"  # healthy, degraded, critical

    @property
    def status_icon(self) -> str:
        """Return a visual indicator for overall system health."""
        if self.overall_status == "healthy":
            return "🟢 HEALTHY"
        if self.overall_status == "degraded":
            return "🟡 DEGRADED"
        if self.overall_status == "critical":
            return "🔴 CRITICAL"
        return "⏹ UNKNOWN"


class ProviderHealthDashboard:
    """
    Real-time provider health dashboard for monitoring the TorShield
    AI gateway infrastructure.

    Aggregates health data from all providers, circuit breaker states,
    latency metrics, and failure rates into a unified dashboard view.
    """

    PROVIDER_DISPLAY_NAMES = {
        "cerebras": "Cerebras.ai",
        "cloudflare_ai_gateway": "CF AI Gateway",
        "cloudflare_workers_ai": "CF Workers AI",
        "portkey": "Portkey.ai",
    }

    def __init__(self):
        self._history: List[DashboardReport] = []
        self._max_history = 100

    def _get_gateway_stats(self) -> Dict[str, Any]:
        """Fetch current gateway health statistics."""
        try:
            from torshield_ai_gateway.gateway import get_gateway
            gateway = get_gateway()
            return gateway.health_stats()
        except Exception as e:
            log.warning(f"[Dashboard] Could not fetch gateway stats: {e}")
            return {}

    def _get_provider_circuit_state(self, provider_name: str) -> str:
        """Get circuit breaker state for a specific provider."""
        try:
            from torshield_ai_gateway.gateway import get_gateway
            gateway = get_gateway()
            provider = gateway._providers.get(provider_name)
            if provider and hasattr(provider, '_circuit_breaker'):
                return provider._circuit_breaker.state
            return "unknown"
        except Exception:
            return "unknown"

    def _get_provider_latency(self, provider_name: str) -> float:
        """Get average latency for a provider from rotator slots."""
        try:
            from torshield_ai_gateway.gateway import get_gateway
            gateway = get_gateway()
            provider = gateway._providers.get(provider_name)
            if provider and hasattr(provider, '_rotator'):
                slots = provider._rotator.slots
                if slots:
                    active = [s for s in slots if s.total_requests > 0]
                    if active:
                        return sum(s.avg_latency_ms for s in active) / len(active)
            return 0.0
        except Exception:
            return 0.0

    def generate_report(self) -> DashboardReport:
        """
        Generate a comprehensive health dashboard report.

        Returns:
            DashboardReport with current health status of all providers.
        """
        stats = self._get_gateway_stats()
        now = datetime.now(timezone.utc).isoformat()

        report = DashboardReport(
            timestamp=now,
            total_requests=stats.get("total_requests", 0),
            primary_successes=stats.get("primary_successes", 0),
            local_fallback_uses=stats.get("local_fallback_uses", 0),
            all_primary_failed=stats.get("all_primary_failed", 0),
            primary_success_rate=stats.get("primary_success_rate", 0.0),
            degraded_rate=stats.get("degraded_rate", 0.0),
        )

        # Build per-provider snapshots
        available_providers = stats.get("available_providers", [])
        provider_attempts = stats.get("provider_attempts", {})

        for name in ["cerebras", "cloudflare_ai_gateway", "cloudflare_workers_ai", "portkey"]:
            attempts = provider_attempts.get(name, 0)
            circuit = self._get_provider_circuit_state(name)
            latency = self._get_provider_latency(name)

            # Estimate success/failure from gateway stats
            # We don't have per-provider success counts from health_stats,
            # so we estimate based on overall rates
            available = name in available_providers
            snapshot = ProviderHealthSnapshot(
                name=name,
                available=available,
                circuit_state=circuit,
                total_requests=attempts,
                avg_latency_ms=latency,
                last_checked=now,
            )

            if attempts > 0 and report.total_requests > 0:
                snapshot.success_rate = report.primary_success_rate

            report.providers.append(snapshot)

        # Determine overall status
        healthy_count = sum(
            1 for p in report.providers
            if p.available and p.circuit_state != "open"
        )
        total_available = sum(1 for p in report.providers if p.available)

        if total_available == 0:
            report.overall_status = "critical"
        elif report.degraded_rate > 0.5:
            report.overall_status = "critical"
        elif healthy_count < total_available or report.degraded_rate > 0.2:
            report.overall_status = "degraded"
        else:
            report.overall_status = "healthy"

        # Save to history
        self._history.append(report)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        return report

    def print_dashboard(self) -> None:
        """Print a formatted health dashboard to stdout."""
        report = self.generate_report()

        print("\n" + "=" * 72)
        print(f"  TorShield AI Gateway — Provider Health Dashboard")
        print(f"  {report.timestamp}")
        print("=" * 72)
        print(f"  Overall Status: {report.status_icon}")
        print(f"  Primary Success Rate: {report.primary_success_rate:.1%}")
        print(f"  Degraded (LocalAI Fallback) Rate: {report.degraded_rate:.1%}")
        print(f"  Total Requests: {report.total_requests}")
        print("-" * 72)
        print(f"  {'Provider':<25} {'Status':<8} {'Circuit':<12} {'Requests':<10} {'Latency':<10}")
        print("-" * 72)

        for p in report.providers:
            display_name = self.PROVIDER_DISPLAY_NAMES.get(p.name, p.name)
            status = p.health_icon
            circuit = p.circuit_state
            requests = str(p.total_requests)
            latency = f"{p.avg_latency_ms:.0f}ms" if p.avg_latency_ms > 0 else "N/A"
            print(f"  {display_name:<25} {status:<8} {circuit:<12} {requests:<10} {latency:<10}")

        print("-" * 72)

        if report.local_fallback_uses > 0:
            print(f"  ⚠ LocalAIEngine used {report.local_fallback_uses} times (DEGRADED mode)")
        if report.all_primary_failed > 0:
            print(f"  ⚠ All primary providers failed {report.all_primary_failed} time(s)")
        print("=" * 72 + "\n")

    def save_report(self, path: Optional[str] = None) -> str:
        """
        Save the current dashboard report to a JSON file.

        Args:
            path: Output file path. Defaults to data/dashboard_report.json.

        Returns:
            Path to the saved report file.
        """
        report = self.generate_report()
        output_path = Path(path) if path else DATA_DIR / "dashboard_report.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = asdict(report)
        output_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        log.info(f"[Dashboard] Report saved to {output_path}")
        return str(output_path)

    def get_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Return the last N dashboard reports as dictionaries.

        Args:
            limit: Maximum number of historical reports to return.

        Returns:
            List of report dictionaries, most recent last.
        """
        return [asdict(r) for r in self._history[-limit:]]


def run_dashboard() -> None:
    """Entry point for running the dashboard from command line."""
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s — %(message)s",
    )
    dashboard = ProviderHealthDashboard()
    dashboard.print_dashboard()
    dashboard.save_report()


if __name__ == "__main__":
    run_dashboard()
