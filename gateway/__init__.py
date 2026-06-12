"""
gateway — Re-exports from torshield_ai_gateway.gateway

Provides convenient access to the TorShield AI Gateway facade
from the organized enterprise structure.

Usage:
    from gateway import TorShieldAIGateway, get_gateway

All original imports remain functional:
    from torshield_ai_gateway.gateway import TorShieldAIGateway  # still works
"""

from torshield_ai_gateway.gateway import (
    TorShieldAIGateway,
    get_gateway,
)

__all__ = [
    "TorShieldAIGateway",
    "get_gateway",
]
