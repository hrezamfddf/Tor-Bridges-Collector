"""
tests/test_providers.py — Comprehensive provider tests with mocked HTTP responses

Tests each provider with various HTTP response codes and scenarios:
  - Cerebras with 200, 400, 404, 403, 401 responses
  - CF Workers AI with various responses
  - CF AI Gateway with URL validation
  - Portkey with auth validation
  - Circuit breaker opening/closing
  - Model fallback chain

All tests use unittest.mock to avoid making real API calls.
"""

import json
import os
import sys
import time
import unittest
from unittest.mock import MagicMock, Mock, patch

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestProviderCircuitBreaker(unittest.TestCase):
    """Test the ProviderCircuitBreaker class."""

    def _get_cb_class(self):
        from torshield_ai_gateway.providers import ProviderCircuitBreaker
        return ProviderCircuitBreaker

    def test_initial_state_is_closed(self):
        CB = self._get_cb_class()
        cb = CB("test_provider")
        self.assertEqual(cb.state, "closed")
        self.assertEqual(cb.failure_count, 0)
        self.assertTrue(cb.allow_request())

    def test_record_success_resets_state(self):
        CB = self._get_cb_class()
        cb = CB("test_provider", failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        self.assertEqual(cb.state, "closed")
        self.assertEqual(cb.failure_count, 0)

    def test_opens_after_threshold_failures(self):
        CB = self._get_cb_class()
        cb = CB("test_provider", failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "closed")
        cb.record_failure()
        self.assertEqual(cb.state, "open")
        self.assertFalse(cb.allow_request())

    def test_open_circuit_rejects_requests(self):
        CB = self._get_cb_class()
        cb = CB("test_provider", failure_threshold=2)
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "open")
        self.assertFalse(cb.allow_request())

    def test_half_open_after_recovery_timeout(self):
        CB = self._get_cb_class()
        cb = CB("test_provider", failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "open")

        # Wait for recovery timeout
        time.sleep(0.02)

        self.assertTrue(cb.allow_request())
        self.assertEqual(cb.state, "half_open")

    def test_half_open_allows_request(self):
        CB = self._get_cb_class()
        cb = CB("test_provider", failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        # Should transition to half_open and allow the request
        self.assertTrue(cb.allow_request())

    def test_success_in_half_open_closes_circuit(self):
        CB = self._get_cb_class()
        cb = CB("test_provider", failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        cb.allow_request()  # triggers half_open
        cb.record_success()
        self.assertEqual(cb.state, "closed")

    def test_failure_in_half_open_reopens_circuit(self):
        CB = self._get_cb_class()
        cb = CB("test_provider", failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        cb.allow_request()  # triggers half_open
        cb.record_failure()
        self.assertEqual(cb.state, "open")

    def test_custom_failure_threshold(self):
        CB = self._get_cb_class()
        cb = CB("test_provider", failure_threshold=10)
        for _ in range(9):
            cb.record_failure()
        self.assertEqual(cb.state, "closed")
        cb.record_failure()
        self.assertEqual(cb.state, "open")

    def test_last_failure_time_updated(self):
        CB = self._get_cb_class()
        cb = CB("test_provider")
        before = time.time()
        cb.record_failure()
        after = time.time()
        self.assertGreaterEqual(cb.last_failure_time, before)
        self.assertLessEqual(cb.last_failure_time, after)


class TestCerebrasProvider(unittest.TestCase):
    """Test CerebrasProvider with mocked HTTP responses."""

    # CerebrasProvider uses build_rotator_from_env("CEREBRAS") which
    # reads CEREBRAS_API_KEY_{i} environment variables.
    CEREBRAS_ENV = {
        "CEREBRAS_API_KEY_1": "test-cerebras-key-12345678",
    }

    @patch.dict(os.environ, CEREBRAS_ENV)
    @patch("urllib.request.urlopen")
    def test_cerebras_200_success(self, mock_urlopen):
        """Test Cerebras with a successful 200 response."""
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = json.dumps({
            "choices": [{"message": {"content": "TORSHIELD_OK test response"}}]
        }).encode("utf-8")
        mock_resp.__enter__ = Mock(return_value=mock_resp)
        mock_resp.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_resp

        from torshield_ai_gateway.providers import CerebrasProvider
        provider = CerebrasProvider()

        result = provider.chat_complete(
            messages=[{"role": "user", "content": "Hello"}],
        )
        self.assertIsNotNone(result)
        self.assertIn("TORSHIELD_OK", result)

    @patch.dict(os.environ, CEREBRAS_ENV)
    def test_cerebras_400_error(self):
        """Test Cerebras with a 400 error response."""
        import urllib.error
        from torshield_ai_gateway.providers import CerebrasProvider, _BaseProvider

        with patch.object(_BaseProvider, '_post_json_with_retry') as mock_post:
            mock_post.side_effect = urllib.error.HTTPError(
                url="https://api.cerebras.ai/v1/chat/completions",
                code=400,
                msg="Bad Request",
                hdrs={},
                fp=None,
            )
            provider = CerebrasProvider()
            with self.assertRaises(urllib.error.HTTPError):
                provider.chat_complete(
                    messages=[{"role": "user", "content": "Hello"}],
                )

    @patch.dict(os.environ, CEREBRAS_ENV)
    def test_cerebras_401_unauthorized(self):
        """Test Cerebras with a 401 unauthorized error."""
        import urllib.error
        from torshield_ai_gateway.providers import CerebrasProvider, _BaseProvider

        with patch.object(_BaseProvider, '_post_json_with_retry') as mock_post:
            mock_post.side_effect = urllib.error.HTTPError(
                url="https://api.cerebras.ai/v1/chat/completions",
                code=401,
                msg="Unauthorized",
                hdrs={},
                fp=None,
            )
            provider = CerebrasProvider()
            with self.assertRaises(urllib.error.HTTPError):
                provider.chat_complete(
                    messages=[{"role": "user", "content": "Hello"}],
                )

    @patch.dict(os.environ, CEREBRAS_ENV)
    def test_cerebras_403_forbidden(self):
        """Test Cerebras with a 403 forbidden error."""
        import urllib.error
        from torshield_ai_gateway.providers import CerebrasProvider, _BaseProvider

        with patch.object(_BaseProvider, '_post_json_with_retry') as mock_post:
            mock_post.side_effect = urllib.error.HTTPError(
                url="https://api.cerebras.ai/v1/chat/completions",
                code=403,
                msg="Forbidden",
                hdrs={},
                fp=None,
            )
            provider = CerebrasProvider()
            with self.assertRaises(urllib.error.HTTPError):
                provider.chat_complete(
                    messages=[{"role": "user", "content": "Hello"}],
                )

    @patch.dict(os.environ, CEREBRAS_ENV)
    def test_cerebras_404_model_not_found(self):
        """Test Cerebras with a 404 model not found error."""
        import urllib.error
        from torshield_ai_gateway.providers import CerebrasProvider, _BaseProvider

        with patch.object(_BaseProvider, '_post_json_with_retry') as mock_post:
            mock_post.side_effect = urllib.error.HTTPError(
                url="https://api.cerebras.ai/v1/chat/completions",
                code=404,
                msg="Not Found",
                hdrs={},
                fp=None,
            )
            provider = CerebrasProvider()
            with self.assertRaises(urllib.error.HTTPError):
                provider.chat_complete(
                    messages=[{"role": "user", "content": "Hello"}],
                )

    def test_cerebras_no_api_key(self):
        """Test Cerebras initialization without API key raises ValueError."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("CEREBRAS_API_KEY_1", None)
            from torshield_ai_gateway.providers import CerebrasProvider
            # AccountRotator raises ValueError when no slots configured
            with self.assertRaises(ValueError):
                CerebrasProvider()


class TestCFWorkersAIProvider(unittest.TestCase):
    """Test Cloudflare Workers AI provider with mocked responses."""

    CF_ENV = {
        "CF_ACCOUNT_ID_1": "test-account-1234567890abcdef",
        "CF_API_TOKEN_1": "test-cf-api-token-1234567890abcdefghij",
    }

    @patch.dict(os.environ, CF_ENV)
    def test_cf_workers_429_rate_limited(self):
        """Test CF Workers AI with rate limiting (429)."""
        import urllib.error
        from torshield_ai_gateway.providers import CloudflareWorkersAIProvider, _BaseProvider

        with patch.object(_BaseProvider, '_post_json_with_retry') as mock_post:
            mock_post.side_effect = urllib.error.HTTPError(
                url="https://api.cloudflare.com/client/v4/accounts/test/models/run",
                code=429,
                msg="Too Many Requests",
                hdrs={},
                fp=None,
            )
            provider = CloudflareWorkersAIProvider()
            with self.assertRaises(urllib.error.HTTPError):
                provider.chat_complete(
                    messages=[{"role": "user", "content": "Hello"}],
                )

    @patch.dict(os.environ, CF_ENV)
    def test_cf_workers_500_server_error(self):
        """Test CF Workers AI with server error (500)."""
        import urllib.error
        from torshield_ai_gateway.providers import CloudflareWorkersAIProvider, _BaseProvider

        with patch.object(_BaseProvider, '_post_json_with_retry') as mock_post:
            mock_post.side_effect = urllib.error.HTTPError(
                url="https://api.cloudflare.com/client/v4/accounts/test/models/run",
                code=500,
                msg="Internal Server Error",
                hdrs={},
                fp=None,
            )
            provider = CloudflareWorkersAIProvider()
            with self.assertRaises(urllib.error.HTTPError):
                provider.chat_complete(
                    messages=[{"role": "user", "content": "Hello"}],
                )

    def test_cf_workers_no_config_raises(self):
        """Test CF Workers AI without config raises ValueError."""
        with patch.dict(os.environ, {}, clear=True):
            from torshield_ai_gateway.providers import CloudflareWorkersAIProvider
            with self.assertRaises(ValueError):
                CloudflareWorkersAIProvider()


class TestCFAIGatewayProvider(unittest.TestCase):
    """Test Cloudflare AI Gateway provider with URL validation."""

    def test_url_validation_valid(self):
        """Test that valid HTTPS URLs pass validation."""
        from torshield_ai_gateway.providers import _validate_url
        url = _validate_url("https://gateway.ai.cloudflare.com/v1/abc123/my-gateway", "test")
        self.assertTrue(url.startswith("https://"))

    def test_url_validation_invalid_no_https(self):
        """Test that non-HTTPS URLs are rejected."""
        from torshield_ai_gateway.providers import _validate_url
        with self.assertRaises(ValueError):
            _validate_url("http://gateway.ai.cloudflare.com/v1/abc123/gw", "test")

    def test_url_validation_strips_trailing_slash(self):
        """Test that trailing slashes are stripped."""
        from torshield_ai_gateway.providers import _validate_url
        url = _validate_url("https://gateway.ai.cloudflare.com/v1/abc123/gw/", "test")
        self.assertFalse(url.endswith("/"))


class TestPortkeyProvider(unittest.TestCase):
    """Test Portkey provider with auth validation."""

    PORTKEY_ENV = {
        "PORTKEY_API_KEY_1": "pk-test-portkey-key-12345678",
    }

    @patch.dict(os.environ, PORTKEY_ENV)
    def test_portkey_key_validation_valid(self):
        """Test Portkey key validation with valid pk- prefix."""
        from torshield_ai_gateway.providers import PortkeyProvider
        provider = PortkeyProvider()
        issues = provider._validate_portkey_key("pk-abc-xyz-12345678", slot_index=1)
        self.assertIsInstance(issues, list)

    @patch.dict(os.environ, PORTKEY_ENV)
    def test_portkey_key_validation_empty(self):
        """Test Portkey key validation with empty key."""
        from torshield_ai_gateway.providers import PortkeyProvider
        provider = PortkeyProvider()
        issues = provider._validate_portkey_key("", slot_index=1)
        self.assertIsInstance(issues, list)
        self.assertGreater(len(issues), 0)

    @patch.dict(os.environ, PORTKEY_ENV)
    def test_portkey_key_validation_no_prefix(self):
        """Test Portkey key validation without pk- prefix.

        Since v14.0, Portkey gateway keys can have ANY prefix (not just pk-).
        A non-pk- key with sufficient length should pass validation.
        """
        from torshield_ai_gateway.providers import PortkeyProvider
        provider = PortkeyProvider()
        issues = provider._validate_portkey_key("sk-valid-long-key-12345678", slot_index=1)
        self.assertIsInstance(issues, list)
        # Non-pk- keys are now ACCEPTED (v14.0 fix) — no prefix warning expected
        # Only format issues (newlines, too-short, whitespace) produce warnings
        self.assertEqual(len(issues), 0)  # Valid key regardless of prefix

    @patch.dict(os.environ, PORTKEY_ENV)
    def test_portkey_key_validation_newline(self):
        """Test Portkey key validation detects newlines."""
        from torshield_ai_gateway.providers import PortkeyProvider
        provider = PortkeyProvider()
        issues = provider._validate_portkey_key("pk-abc\nxyz", slot_index=1)
        self.assertIsInstance(issues, list)
        # Should detect newline
        has_newline_issue = any("newline" in issue.lower() for issue in issues)
        self.assertTrue(has_newline_issue)

    def test_portkey_no_api_key(self):
        """Test Portkey initialization without API key raises ValueError."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("PORTKEY_API_KEY_1", None)
            from torshield_ai_gateway.providers import PortkeyProvider
            # AccountRotator raises ValueError when no slots configured
            with self.assertRaises(ValueError):
                PortkeyProvider()


class TestModelFallbackChain(unittest.TestCase):
    """Test model fallback chain across providers."""

    def test_stable_models_list_exists(self):
        """Test that CF_STABLE_MODELS fallback list is populated."""
        from torshield_ai_gateway.providers import CF_STABLE_MODELS
        self.assertIsInstance(CF_STABLE_MODELS, list)
        self.assertGreater(len(CF_STABLE_MODELS), 0)
        for model in CF_STABLE_MODELS:
            self.assertTrue(model.startswith("@cf/"))

    def test_mask_key(self):
        """Test API key masking for log safety."""
        from torshield_ai_gateway.providers import _mask_key
        # Long key
        self.assertEqual(_mask_key("abcdefghijklmnop"), "abcd...mnop")
        # Short key
        result = _mask_key("ab")
        self.assertIn("***", result)
        # Empty key
        self.assertEqual(_mask_key(""), "<EMPTY>")

    def test_backoff_delay_computation(self):
        """Test exponential backoff delay computation."""
        from torshield_ai_gateway.providers import _compute_backoff_delay
        d0 = _compute_backoff_delay(0)
        d1 = _compute_backoff_delay(1)
        d2 = _compute_backoff_delay(2)
        self.assertLess(d0, d1)
        self.assertLess(d1, d2)

    def test_retryable_http_codes(self):
        """Test that correct HTTP codes are marked as retryable."""
        from torshield_ai_gateway.providers import RETRYABLE_HTTP_CODES
        self.assertIn(429, RETRYABLE_HTTP_CODES)
        self.assertIn(500, RETRYABLE_HTTP_CODES)
        self.assertIn(502, RETRYABLE_HTTP_CODES)
        self.assertIn(503, RETRYABLE_HTTP_CODES)
        self.assertIn(504, RETRYABLE_HTTP_CODES)
        # Auth errors should NOT be retryable
        self.assertNotIn(400, RETRYABLE_HTTP_CODES)
        self.assertNotIn(401, RETRYABLE_HTTP_CODES)
        self.assertNotIn(403, RETRYABLE_HTTP_CODES)

    def test_auth_failure_codes_defined(self):
        """Test that AUTH_FAILURE_HTTP_CODES is defined and contains 401, 403."""
        from torshield_ai_gateway.providers import AUTH_FAILURE_HTTP_CODES
        self.assertIn(401, AUTH_FAILURE_HTTP_CODES)
        self.assertIn(403, AUTH_FAILURE_HTTP_CODES)
        # Retryable codes must NOT overlap with auth failure codes
        from torshield_ai_gateway.providers import RETRYABLE_HTTP_CODES
        self.assertEqual(AUTH_FAILURE_HTTP_CODES & RETRYABLE_HTTP_CODES, set())

    def test_401_not_retried_in_post_json(self):
        """Test that 401 is NEVER retried in _post_json_with_retry."""
        from torshield_ai_gateway.providers import _BaseProvider
        import urllib.error

        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"error": "unauthorized"}'

        with patch("urllib.request.urlopen") as mock_urlopen:
            error = urllib.error.HTTPError(
                url="https://api.test.com/v1/chat/completions",
                code=401,
                msg="Unauthorized",
                hdrs={},
                fp=None,
            )
            mock_urlopen.side_effect = error

            # Should raise immediately on 401 without retry
            with self.assertRaises(urllib.error.HTTPError):
                _BaseProvider._post_json_with_retry(
                    url="https://api.test.com/v1/chat/completions",
                    headers={"Content-Type": "application/json"},
                    payload={"model": "test", "messages": []},
                    timeout=10,
                    provider_name="test_provider",
                    slot_index=1,
                    max_retries=3,
                )
            # Should only be called once (no retries)
            self.assertEqual(mock_urlopen.call_count, 1)

    def test_403_not_retried_in_post_json(self):
        """Test that 403 is NEVER retried in _post_json_with_retry (except CF bot)."""
        from torshield_ai_gateway.providers import _BaseProvider
        import urllib.error

        with patch("urllib.request.urlopen") as mock_urlopen:
            error = urllib.error.HTTPError(
                url="https://api.test.com/v1/chat/completions",
                code=403,
                msg="Forbidden",
                hdrs={},
                fp=None,
            )
            # Set up the error to have a readable body without CF bot code
            error.read = Mock(return_value=b'{"error": "forbidden"}')
            mock_urlopen.side_effect = error

            with self.assertRaises(urllib.error.HTTPError):
                _BaseProvider._post_json_with_retry(
                    url="https://api.test.com/v1/chat/completions",
                    headers={"Content-Type": "application/json"},
                    payload={"model": "test", "messages": []},
                    timeout=10,
                    provider_name="test_provider",
                    slot_index=1,
                    max_retries=3,
                )
            # Should only be called once (no retries for genuine 403)
            self.assertEqual(mock_urlopen.call_count, 1)


class TestExtractText(unittest.TestCase):
    """Test the _extract_text response parsing utility."""

    def test_openai_format(self):
        """Test parsing OpenAI-format response."""
        from torshield_ai_gateway.providers import _BaseProvider
        response = {"choices": [{"message": {"content": "Hello world"}}]}
        self.assertEqual(_BaseProvider._extract_text(response), "Hello world")

    def test_cf_format(self):
        """Test parsing Cloudflare-format response."""
        from torshield_ai_gateway.providers import _BaseProvider
        response = {"result": {"response": "Hello world"}}
        self.assertEqual(_BaseProvider._extract_text(response), "Hello world")

    def test_fallback_to_str(self):
        """Test fallback to string representation."""
        from torshield_ai_gateway.providers import _BaseProvider
        response = {"unknown": "format"}
        result = _BaseProvider._extract_text(response)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)


class TestCFPreFlightValidation(unittest.TestCase):
    """Test CF pre-flight validation for 11 slots."""

    def test_validate_cf_slot_valid(self):
        """Test that a valid CF slot passes pre-flight."""
        from torshield_ai_gateway.providers import validate_cf_slot
        result = validate_cf_slot(
            1,
            account_id="abcdef1234567890abcdef12",
            token="valid-cf-api-token-1234567890abcdefghij",
            gateway_url="https://gateway.ai.cloudflare.com/v1/abcdef1234567890abcdef12/my-gateway",
        )
        self.assertTrue(result)

    def test_validate_cf_slot_short_account_id(self):
        """Test that a short account_id fails pre-flight."""
        from torshield_ai_gateway.providers import validate_cf_slot
        result = validate_cf_slot(
            7,
            account_id="short",
            token="valid-cf-api-token-1234567890abcdefghij",
        )
        self.assertFalse(result)

    def test_validate_cf_slot_short_token(self):
        """Test that a short token fails pre-flight."""
        from torshield_ai_gateway.providers import validate_cf_slot
        result = validate_cf_slot(
            7,
            account_id="abcdef1234567890abcdef12",
            token="short",
        )
        self.assertFalse(result)

    def test_validate_cf_slot_invalid_gateway_prefix(self):
        """Test that an invalid gateway URL prefix fails pre-flight."""
        from torshield_ai_gateway.providers import validate_cf_slot
        result = validate_cf_slot(
            1,
            account_id="abcdef1234567890abcdef12",
            token="valid-cf-api-token-1234567890abcdefghij",
            gateway_url="https://invalid.example.com/v1/abc/gw",
        )
        self.assertFalse(result)

    def test_validate_cf_slot_gateway_missing_slug(self):
        """Test that a gateway URL without slug fails pre-flight."""
        from torshield_ai_gateway.providers import validate_cf_slot
        result = validate_cf_slot(
            1,
            account_id="abcdef1234567890abcdef12",
            token="valid-cf-api-token-1234567890abcdefghij",
            gateway_url="https://gateway.ai.cloudflare.com/v1/abcdef1234567890abcdef12/",
        )
        self.assertFalse(result)

    def test_validate_cf_slot_no_gateway_url(self):
        """Test that omitting gateway_url still passes (only acct+token required for Workers AI)."""
        from torshield_ai_gateway.providers import validate_cf_slot
        result = validate_cf_slot(
            1,
            account_id="abcdef1234567890abcdef12",
            token="valid-cf-api-token-1234567890abcdefghij",
            gateway_url="",
        )
        self.assertTrue(result)

    def test_load_cf_slots_filters_invalid(self):
        """Test _load_cf_slots filters out invalid slots."""
        from torshield_ai_gateway.providers import _load_cf_slots
        # Test with mixed env vars
        test_env = {
            "CF_ACCOUNT_ID_1": "valid-account-id-1234567890ab",
            "CF_API_TOKEN_1": "valid-cf-api-token-1234567890abcdefghij",
            "CF_ACCOUNT_ID_7": "short",
            "CF_API_TOKEN_7": "also-short",
        }
        with patch.dict(os.environ, test_env, clear=False):
            slots = _load_cf_slots(11)
            # Slot 7 should be filtered out; slot 1 should pass
            slot_indices = [s["index"] for s in slots]
            self.assertIn(1, slot_indices)
            self.assertNotIn(7, slot_indices)


class TestExponentialBackoffWithJitter(unittest.TestCase):
    """Test the jitter-based exponential backoff."""

    def test_backoff_increases_with_attempts(self):
        """Test that backoff delay increases with attempt number."""
        from torshield_ai_gateway.providers import _exponential_backoff_with_jitter
        delays = [_exponential_backoff_with_jitter(i) for i in range(5)]
        # Generally increasing (with jitter, not strict monotonic)
        self.assertGreater(delays[4], delays[0])

    def test_backoff_capped_at_30(self):
        """Test that backoff never exceeds 30 seconds."""
        from torshield_ai_gateway.providers import _exponential_backoff_with_jitter
        for i in range(20):
            delay = _exponential_backoff_with_jitter(i)
            self.assertLessEqual(delay, 30.0)

    def test_backoff_with_jitter_non_negative(self):
        """Test that backoff is always non-negative."""
        from torshield_ai_gateway.providers import _exponential_backoff_with_jitter
        for i in range(20):
            delay = _exponential_backoff_with_jitter(i)
            self.assertGreaterEqual(delay, 0.0)


class TestPortkeyBuildHeaders(unittest.TestCase):
    """Test the Portkey _build_portkey_headers method."""

    def test_pk_prefix_uses_portkey_header(self):
        """Test that pk- keys use x-portkey-api-key header."""
        from torshield_ai_gateway.providers import PortkeyProvider
        headers = PortkeyProvider._build_portkey_headers("pk-test-key-12345678")
        self.assertIn("x-portkey-api-key", headers)
        self.assertEqual(headers["x-portkey-api-key"], "pk-test-key-12345678")

    def test_non_pk_uses_bearer_auth(self):
        """Test that non-pk- keys use Bearer auth."""
        from torshield_ai_gateway.providers import PortkeyProvider
        headers = PortkeyProvider._build_portkey_headers("sk-valid-long-key-12345678")
        self.assertIn("Authorization", headers)
        self.assertTrue(headers["Authorization"].startswith("Bearer "))

    def test_provider_header_not_set_for_openai(self):
        """Test that x-portkey-provider is NOT set for openai (default)."""
        from torshield_ai_gateway.providers import PortkeyProvider
        headers = PortkeyProvider._build_portkey_headers("pk-test-key-12345678")
        self.assertNotIn("x-portkey-provider", headers)

    def test_provider_header_set_for_non_openai(self):
        """Test that x-portkey-provider is set for non-openai providers."""
        from torshield_ai_gateway.providers import PortkeyProvider
        headers = PortkeyProvider._build_portkey_headers(
            "pk-test-key-12345678", provider="cloudflare-ai"
        )
        self.assertIn("x-portkey-provider", headers)
        self.assertEqual(headers["x-portkey-provider"], "cloudflare-ai")


if __name__ == "__main__":
    unittest.main()
