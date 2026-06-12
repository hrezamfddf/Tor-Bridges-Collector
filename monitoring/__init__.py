"""
monitoring — Health monitoring and diagnostics for TorShield

Re-exports from the health check system and provides a provider
health dashboard for real-time monitoring.

Usage:
    from monitoring.health_check import ExponentialBackoffRetry
    from monitoring.provider_dashboard import ProviderHealthDashboard
    from monitoring.structured_logging import (
        StructuredJsonFormatter,
        ProviderHealthMetrics,
        PerformanceReport,
        FailureAnalytics,
        HealthReportGenerator,
    )

All original imports remain functional:
    from scripts.ai_gateway_health_check import ExponentialBackoffRetry  # still works
"""

from monitoring.health_check import (
    ExponentialBackoffRetry,
    AuthFailureDiagnostics,
    EnvVarValidator,
)

from monitoring.provider_dashboard import ProviderHealthDashboard

from monitoring.structured_logging import (
    StructuredJsonFormatter,
    ProviderHealthMetrics,
    PerformanceReport,
    FailureAnalytics,
    HealthReportGenerator,
)

__all__ = [
    "ExponentialBackoffRetry",
    "AuthFailureDiagnostics",
    "EnvVarValidator",
    "ProviderHealthDashboard",
    "StructuredJsonFormatter",
    "ProviderHealthMetrics",
    "PerformanceReport",
    "FailureAnalytics",
    "HealthReportGenerator",
]
