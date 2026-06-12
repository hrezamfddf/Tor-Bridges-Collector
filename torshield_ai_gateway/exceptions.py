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
  BadRequestError             — HTTP 400 bad request, not an auth failure
"""

from __future__ import annotations


class ProviderConfigurationError(Exception):
    """
    Raised when provider setup is permanently invalid for this run.

    This is a configuration-level error that will NOT be fixed by retrying.
    Examples:
      - All API keys are too short (e.g., Portkey keys < 16 chars)
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


class BadRequestError(Exception):
    """
    Raised when provider returns HTTP 400 Bad Request.

    This is a request-level error (wrong model, malformed payload, bad URL path)
    and is NOT an authentication failure. It should be distinguished from 401/403
    so the caller can decide to try a different model instead of skipping the slot.

    The caller should catch this exception and try the next model in the fallback
    chain, rather than skipping the entire slot (which is the correct behavior
    for auth failures).
    """

    def __init__(self, message: str = "", *, provider: str = "", slot: int = 0) -> None:
        self.provider = provider
        self.slot = slot
        super().__init__(message)
