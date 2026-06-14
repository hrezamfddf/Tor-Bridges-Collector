# core package

# ── New TorShield-IR modules (ADDITIVE, non-destructive) ──
from .endpoint_validator import (
    EndpointValidator,
    EndpointType,
    EndpointValidationResult,
    get_validator,
    validate_slot,
)

__all__ = [
    # Endpoint Validation Layer
    "EndpointValidator",
    "EndpointType",
    "EndpointValidationResult",
    "get_validator",
    "validate_slot",
]
