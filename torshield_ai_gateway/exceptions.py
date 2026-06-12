"""
exceptions.py — TorShield AI Gateway Exception Hierarchy
=========================================================

Custom exceptions for the AI gateway provider system.
These exceptions enable fine-grained error handling, especially
distinguishing between transient network errors (which should be
retried) and permanent configuration errors (which must NOT be
retried because the configuration will not change mid-run).

Exception Hierarchy:
  ProviderConfigurationError  — permanent setup failure, never retry
"""

from __future__ import annotations


class ProviderConfigurationError(Exception):
    """
    Raised when provider setup is permanently invalid for this run.

    This is a configuration-level error that will NOT be fixed by retrying.
    Examples:
      - All API keys have wrong format (e.g., Portkey keys without 'pk-' prefix)
      - No slots configured (all failed pre-flight screening)
      - All Cloudflare slots returned HTTP 400 with empty body (bad URL path)

    The health check catches this exception and classifies the provider as
    "skipped" (not a failure), allowing the overall CI run to exit 0 if at
    least one other provider is healthy.

    This exception MUST NOT be retried — the configuration will not change
    mid-run. The fix must come from updating GitHub Secrets or the provider
    configuration before the next CI run.
    """

    def __init__(self, message: str = "", *, provider: str = "") -> None:
        self.provider = provider
        super().__init__(message)
