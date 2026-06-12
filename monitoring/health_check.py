"""
monitoring.health_check — Re-exports from scripts.ai_gateway_health_check

Provides convenient access to health check utilities from the
organized enterprise structure.

Usage:
    from monitoring.health_check import ExponentialBackoffRetry
    from monitoring.health_check import AuthFailureDiagnostics
    from monitoring.health_check import EnvVarValidator
    from monitoring.health_check import is_valid_ai_response

All original imports remain functional:
    from scripts.ai_gateway_health_check import ExponentialBackoffRetry  # still works
"""

import importlib
import sys
import os

# Ensure project root is on sys.path for the import
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# Import from the original location
_health_check_module = importlib.import_module("scripts.ai_gateway_health_check")

ExponentialBackoffRetry = _health_check_module.ExponentialBackoffRetry
AuthFailureDiagnostics = _health_check_module.AuthFailureDiagnostics
EnvVarValidator = _health_check_module.EnvVarValidator

# Also export the main check function and TORSHIELD_OK constant if available
TORSHIELD_OK = getattr(_health_check_module, "TORSHIELD_OK", "TORSHIELD_OK")
check_all_providers = getattr(_health_check_module, "check_all_providers", None)

# v14.0: Flexible AI response validation (replaces strict TORSHIELD_OK check)
is_valid_ai_response = getattr(_health_check_module, "is_valid_ai_response", None)

__all__ = [
    "ExponentialBackoffRetry",
    "AuthFailureDiagnostics",
    "EnvVarValidator",
    "TORSHIELD_OK",
    "check_all_providers",
    "is_valid_ai_response",
]
