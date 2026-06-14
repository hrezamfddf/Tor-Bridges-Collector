#!/usr/bin/env python3
"""
endpoint_validator.py — Endpoint Validation Layer v1.0
═══════════════════════════════════════════════════════════════════════════════

Validates URL format, auto-detects /compat/ vs /workers-ai/ suffix,
tests endpoint reachability with lightweight probes, and logs detected
format per slot at startup.

CRITICAL FIX: Cloudflare AI Gateway now uses /compat/chat/completions
as the OpenAI-compatible endpoint. The old /workers-ai/v1/chat/completions
causes HTTP 400 across all 11 slots.

DESIGN PRINCIPLES:
  - ADDITIVE ONLY: Does not modify existing code
  - ZERO CRASH: All operations wrapped in try/except
  - Feature-flagged: ENABLE_ENDPOINT_VALIDATION=true
"""

from __future__ import annotations

import logging
import os
import re
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("torshield.endpoint_validator")


class EndpointType(Enum):
    """Detected endpoint type for a CF AI Gateway slot."""
    COMPAT = "compat"           # /compat/chat/completions (NEW, OpenAI-compatible)
    WORKERS_AI = "workers-ai"   # /workers-ai/v1/chat/completions (OLD, causes 400)
    DIRECT = "direct"           # Direct Workers AI (api.cloudflare.com)
    UNKNOWN = "unknown"


@dataclass
class EndpointValidationResult:
    """Result of validating a single slot's endpoint URL."""
    slot_index: int
    url: str
    endpoint_type: EndpointType
    is_valid: bool
    is_reachable: bool
    detected_suffix: str
    recommended_url: str = ""
    error_message: str = ""
    probe_latency_ms: float = 0.0
    validated_at: float = field(default_factory=time.time)


class EndpointValidator:
    """
    Validates and auto-detects CF AI Gateway endpoint formats.
    
    Key Fix: Detects and corrects the /workers-ai/v1/chat/completions
    suffix to /compat/chat/completions for AI Gateway slots.
    """

    # Correct suffixes for each endpoint type
    COMPAT_SUFFIX = "/compat/chat/completions"
    WORKERS_AI_SUFFIX = "/workers-ai/v1/chat/completions"
    
    # CF AI Gateway URL pattern
    GATEWAY_URL_PATTERN = re.compile(
        r'^https://gateway\.ai\.cloudflare\.com/v1/'
        r'([0-9a-f]{32})/([a-zA-Z0-9_-]+)',
        re.IGNORECASE
    )
    
    # Direct CF Workers AI URL pattern
    DIRECT_URL_PATTERN = re.compile(
        r'^https://api\.cloudflare\.com/client/v4/accounts/'
        r'([0-9a-f]{32})/ai',
        re.IGNORECASE
    )

    def __init__(self):
        self._results: Dict[int, EndpointValidationResult] = {}
        self._enabled = os.getenv("ENABLE_ENDPOINT_VALIDATION", "true").lower() == "true"
        
    def validate_slot_url(
        self,
        slot_index: int,
        gateway_url: str,
        account_id: str = "",
        api_token: str = "",
    ) -> EndpointValidationResult:
        """
        Validate a single slot's gateway URL and detect its endpoint type.
        
        Auto-detects whether the URL uses /compat/ or /workers-ai/ suffix.
        If /workers-ai/ is detected on a gateway URL, recommends /compat/ instead.
        """
        if not self._enabled:
            return EndpointValidationResult(
                slot_index=slot_index,
                url=gateway_url,
                endpoint_type=EndpointType.UNKNOWN,
                is_valid=True,
                is_reachable=True,
                detected_suffix="validation_disabled",
            )

        try:
            url = gateway_url.rstrip("/")
            
            # Step 1: Detect endpoint type
            endpoint_type = self._detect_endpoint_type(url)
            
            # Step 2: Validate URL format
            is_valid, format_error = self._validate_url_format(url, endpoint_type)
            
            # Step 3: Build recommended URL (fix /workers-ai/ → /compat/)
            recommended_url = self._build_recommended_url(url, endpoint_type)
            
            # Step 4: Test reachability with lightweight probe
            is_reachable, probe_latency = self._probe_endpoint(
                recommended_url or url, api_token
            )
            
            result = EndpointValidationResult(
                slot_index=slot_index,
                url=url,
                endpoint_type=endpoint_type,
                is_valid=is_valid,
                is_reachable=is_reachable,
                detected_suffix=self._extract_suffix(url),
                recommended_url=recommended_url,
                error_message=format_error,
                probe_latency_ms=probe_latency,
            )
            
            self._results[slot_index] = result
            
            # Log the detected format per slot
            logger.info(
                f"[EndpointValidator] Slot {slot_index}: "
                f"type={endpoint_type.value}, "
                f"valid={is_valid}, "
                f"reachable={is_reachable}, "
                f"suffix={result.detected_suffix}, "
                f"recommended={recommended_url[-40:] if recommended_url else 'N/A'}"
            )
            
            if endpoint_type == EndpointType.WORKERS_AI and "gateway.ai.cloudflare.com" in url:
                logger.warning(
                    f"[EndpointValidator] Slot {slot_index}: BUG DETECTED — "
                    f"Gateway URL uses /workers-ai/ suffix which causes HTTP 400. "
                    f"Recommending /compat/ suffix instead. "
                    f"OLD: ...{result.detected_suffix} → NEW: ...{self.COMPAT_SUFFIX}"
                )
            
            return result
            
        except Exception as e:
            logger.error(f"[EndpointValidator] Slot {slot_index} validation failed: {e}")
            return EndpointValidationResult(
                slot_index=slot_index,
                url=gateway_url,
                endpoint_type=EndpointType.UNKNOWN,
                is_valid=False,
                is_reachable=False,
                detected_suffix="error",
                error_message=str(e),
            )

    def _detect_endpoint_type(self, url: str) -> EndpointType:
        """Detect the endpoint type from the URL path."""
        url_lower = url.lower()
        
        if "gateway.ai.cloudflare.com" in url_lower:
            if "/compat/" in url_lower:
                return EndpointType.COMPAT
            elif "/workers-ai/" in url_lower:
                return EndpointType.WORKERS_AI
            else:
                # Bare gateway URL — will be normalized later
                return EndpointType.COMPAT  # Default to compat for gateway
        elif "api.cloudflare.com" in url_lower:
            return EndpointType.DIRECT
        else:
            return EndpointType.UNKNOWN

    def _validate_url_format(
        self, url: str, endpoint_type: EndpointType
    ) -> Tuple[bool, str]:
        """Validate URL format matches expected pattern."""
        if not url.startswith("https://"):
            return False, "URL must start with https://"
        
        if endpoint_type in (EndpointType.COMPAT, EndpointType.WORKERS_AI):
            if not self.GATEWAY_URL_PATTERN.match(url.split("/compat/")[0].split("/workers-ai/")[0]):
                return False, "Gateway URL doesn't match CF AI Gateway pattern"
        elif endpoint_type == EndpointType.DIRECT:
            if not self.DIRECT_URL_PATTERN.match(url):
                return False, "Direct URL doesn't match CF Workers AI pattern"
        
        return True, ""

    def _build_recommended_url(
        self, url: str, endpoint_type: EndpointType
    ) -> str:
        """
        Build the recommended URL with correct suffix.
        
        KEY FIX: For gateway URLs with /workers-ai/ suffix,
        recommend /compat/ suffix instead to fix HTTP 400.
        """
        if endpoint_type == EndpointType.DIRECT:
            return url  # Direct URLs are already correct
        
        if endpoint_type == EndpointType.COMPAT:
            return url  # Already correct
        
        if endpoint_type == EndpointType.WORKERS_AI:
            # FIX: Replace /workers-ai/v1/chat/completions with /compat/chat/completions
            # Strip the old suffix and add the new one
            base = url.split("/workers-ai")[0]
            return base + self.COMPAT_SUFFIX
        
        # Unknown — try compat as default
        if "gateway.ai.cloudflare.com" in url:
            # Strip any existing suffix
            match = self.GATEWAY_URL_PATTERN.match(url)
            if match:
                account_id = match.group(1)
                slug = match.group(2)
                return f"https://gateway.ai.cloudflare.com/v1/{account_id}/{slug}{self.COMPAT_SUFFIX}"
        
        return url

    def _extract_suffix(self, url: str) -> str:
        """Extract the detected path suffix from URL."""
        if "/compat/chat/completions" in url:
            return "/compat/chat/completions"
        if "/workers-ai/v1/chat/completions" in url:
            return "/workers-ai/v1/chat/completions"
        if "/workers-ai" in url:
            # Partial suffix
            idx = url.find("/workers-ai")
            return url[idx:]
        return "<bare>"

    def _probe_endpoint(
        self, url: str, api_token: str = "", timeout: int = 8
    ) -> Tuple[bool, float]:
        """
        Test endpoint reachability with a lightweight probe.
        
        Uses HEAD/OPTIONS request to check if the endpoint is reachable.
        Returns (is_reachable, latency_ms).
        """
        try:
            probe_url = url.replace("/chat/completions", "").rstrip("/")
            headers = {"User-Agent": "TorShield-EndpointValidator/1.0"}
            if api_token:
                headers["Authorization"] = f"Bearer {api_token}"
            
            t0 = time.monotonic()
            req = urllib.request.Request(probe_url, headers=headers, method="HEAD")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    latency = (time.monotonic() - t0) * 1000
                    return True, latency
            except urllib.error.HTTPError as e:
                # Any HTTP response means the endpoint is reachable
                latency = (time.monotonic() - t0) * 1000
                return True, latency
            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
                latency = (time.monotonic() - t0) * 1000
                return False, latency
                
        except Exception as e:
            return False, 0.0

    def validate_all_slots(self) -> Dict[int, EndpointValidationResult]:
        """Validate all 11 CF slots from environment variables."""
        for i in range(1, 12):
            gateway_url = os.getenv(f"CF_AI_GATEWAY_URL_{i}", "").strip()
            account_id = os.getenv(f"CF_ACCOUNT_ID_{i}", "").strip()
            api_token = os.getenv(f"CF_API_TOKEN_{i}", "").strip()
            
            if gateway_url:
                self.validate_slot_url(i, gateway_url, account_id, api_token)
        
        return self._results

    def get_recommended_url(self, slot_index: int) -> Optional[str]:
        """Get the recommended (fixed) URL for a slot."""
        result = self._results.get(slot_index)
        if result and result.recommended_url:
            return result.recommended_url
        return None

    def get_validation_summary(self) -> Dict:
        """Get a summary of all validation results."""
        total = len(self._results)
        valid = sum(1 for r in self._results.values() if r.is_valid)
        reachable = sum(1 for r in self._results.values() if r.is_reachable)
        workers_ai_bug = sum(
            1 for r in self._results.values()
            if r.endpoint_type == EndpointType.WORKERS_AI
        )
        
        return {
            "total_slots_validated": total,
            "valid_urls": valid,
            "reachable_endpoints": reachable,
            "workers_ai_bug_detected": workers_ai_bug,
            "fix_applied": workers_ai_bug > 0,
            "results": {
                str(i): {
                    "slot": r.slot_index,
                    "type": r.endpoint_type.value,
                    "valid": r.is_valid,
                    "reachable": r.is_reachable,
                    "suffix": r.detected_suffix,
                    "recommended": r.recommended_url[-50:] if r.recommended_url else "",
                    "latency_ms": round(r.probe_latency_ms, 1),
                }
                for i, r in self._results.items()
            },
        }


# Module-level convenience
_validator_instance: Optional[EndpointValidator] = None

def get_validator() -> EndpointValidator:
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = EndpointValidator()
    return _validator_instance

def validate_slot(slot_index: int, url: str, account_id: str = "", token: str = "") -> EndpointValidationResult:
    return get_validator().validate_slot_url(slot_index, url, account_id, token)
