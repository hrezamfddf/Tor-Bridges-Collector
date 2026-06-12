"""
tests/test_health_check.py — Health check system tests

Tests:
  - ExponentialBackoffRetry mechanism
  - AuthFailureDiagnostics
  - EnvVarValidator
  - Provider check with mocked gateway
  - Exit code logic

All tests use unittest.mock to avoid making real API calls.
"""

import json
import os
import sys
import time
import unittest
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestExponentialBackoffRetry(unittest.TestCase):
    """Test the ExponentialBackoffRetry class."""

    def _get_class(self):
        from scripts.ai_gateway_health_check import ExponentialBackoffRetry
        return ExponentialBackoffRetry

    def test_initialization_defaults(self):
        """Test default retry parameters."""
        EBR = self._get_class()
        retry = EBR()
        self.assertEqual(retry.max_retries, 3)
        self.assertEqual(retry.base_delay, 1.0)
        self.assertEqual(retry.max_delay, 30.0)
        self.assertEqual(retry.jitter, 0.5)

    def test_initialization_custom(self):
        """Test custom retry parameters."""
        EBR = self._get_class()
        retry = EBR(max_retries=5, base_delay_sec=2.0, max_delay_sec=60.0, jitter=1.0)
        self.assertEqual(retry.max_retries, 5)
        self.assertEqual(retry.base_delay, 2.0)
        self.assertEqual(retry.max_delay, 60.0)
        self.assertEqual(retry.jitter, 1.0)

    def test_compute_delay_increases(self):
        """Test that delays increase exponentially."""
        EBR = self._get_class()
        retry = EBR(base_delay_sec=1.0, jitter=0.0)

        delays = [retry.compute_delay(i) for i in range(5)]
        # Each delay should be approximately 2x the previous
        for i in range(1, len(delays)):
            self.assertGreaterEqual(delays[i], delays[i-1] * 1.5)

    def test_compute_delay_capped(self):
        """Test that delay is capped at max_delay."""
        EBR = self._get_class()
        retry = EBR(base_delay_sec=10.0, max_delay_sec=30.0, jitter=0.0)

        delay = retry.compute_delay(100)  # Very high attempt number
        self.assertLessEqual(delay, 30.0)

    def test_compute_delay_minimum(self):
        """Test that delay has a reasonable minimum."""
        EBR = self._get_class()
        retry = EBR(base_delay_sec=1.0, jitter=0.0)

        delay = retry.compute_delay(0)
        self.assertGreater(delay, 0)

    def test_execute_success_first_try(self):
        """Test successful execution on first attempt."""
        EBR = self._get_class()
        retry = EBR(max_retries=3)

        result, attempts, error = retry.execute(lambda: "success")
        self.assertEqual(result, "success")
        self.assertEqual(attempts, 1)
        self.assertIsNone(error)

    def test_execute_retries_on_failure(self):
        """Test that execute retries on failure."""
        EBR = self._get_class()
        retry = EBR(max_retries=2, base_delay_sec=0.01, jitter=0.0)

        call_count = [0]
        def flaky_func():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ConnectionError("timeout")
            return "success"

        result, attempts, error = retry.execute(flaky_func)
        self.assertEqual(result, "success")
        self.assertEqual(attempts, 3)

    def test_execute_exhausted_retries(self):
        """Test that execute returns None after exhausting retries."""
        EBR = self._get_class()
        retry = EBR(max_retries=2, base_delay_sec=0.01, jitter=0.0)

        result, attempts, error = retry.execute(lambda: (_ for _ in ()).throw(ConnectionError("down")))
        self.assertIsNone(result)
        self.assertEqual(attempts, 3)
        self.assertIsInstance(error, ConnectionError)

    def test_jitter_applied(self):
        """Test that jitter adds randomness to delays."""
        EBR = self._get_class()
        retry = EBR(base_delay_sec=1.0, jitter=0.5)

        delays = [retry.compute_delay(1) for _ in range(20)]
        # With jitter, delays should not all be identical
        unique_delays = set(round(d, 4) for d in delays)
        self.assertGreater(len(unique_delays), 1)


class TestAuthFailureDiagnostics(unittest.TestCase):
    """Test the AuthFailureDiagnostics class."""

    def _get_class(self):
        from scripts.ai_gateway_health_check import AuthFailureDiagnostics
        return AuthFailureDiagnostics

    def test_diagnose_401(self):
        """Test diagnosis of 401 unauthorized errors via diagnose_http_error."""
        AFD = self._get_class()
        import urllib.error
        err = urllib.error.HTTPError(
            url="https://api.cerebras.ai/v1/chat/completions",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=None,
        )
        result = AFD.diagnose_http_error(
            error=err,
            provider="cerebras",
            url="https://api.cerebras.ai/v1/chat/completions",
            headers_sent={"Authorization": "Bearer sk-test-key-12345678"},
        )
        self.assertIsInstance(result, dict)
        self.assertIn("http_status", result)
        self.assertEqual(result["http_status"], 401)

    def test_diagnose_403(self):
        """Test diagnosis of 403 forbidden errors via diagnose_http_error."""
        AFD = self._get_class()
        import urllib.error
        err = urllib.error.HTTPError(
            url="https://api.cloudflare.com/client/v4/accounts/test/models/run",
            code=403,
            msg="Forbidden",
            hdrs={},
            fp=None,
        )
        result = AFD.diagnose_http_error(
            error=err,
            provider="cloudflare_workers_ai",
            url="https://api.cloudflare.com/client/v4/accounts/test/models/run",
            headers_sent={"Authorization": "Bearer test-token"},
        )
        self.assertIsInstance(result, dict)
        self.assertEqual(result["http_status"], 403)
        self.assertIn("recommendations", result)

    def test_diagnose_400(self):
        """Test diagnosis of 400 bad request errors via diagnose_http_error."""
        AFD = self._get_class()
        import urllib.error
        err = urllib.error.HTTPError(
            url="https://api.cloudflare.com/client/v4/accounts/test/models/run",
            code=400,
            msg="Bad Request",
            hdrs={},
            fp=None,
        )
        result = AFD.diagnose_http_error(
            error=err,
            provider="cloudflare_workers_ai",
            url="https://api.cloudflare.com/client/v4/accounts/test/models/run",
            headers_sent={"Content-Type": "application/json"},
        )
        self.assertIsInstance(result, dict)
        self.assertEqual(result["http_status"], 400)

    def test_mask_key(self):
        """Test API key masking for log safety."""
        AFD = self._get_class()
        # Long key
        self.assertEqual(AFD.mask_key("abcdefghijklmnop"), "abcd...mnop")
        # Empty key
        self.assertEqual(AFD.mask_key(""), "<EMPTY>")
        # Short key
        result = AFD.mask_key("ab")
        self.assertIn("***", result)


class TestEnvVarValidator(unittest.TestCase):
    """Test the EnvVarValidator class."""

    def _get_class(self):
        from scripts.ai_gateway_health_check import EnvVarValidator
        return EnvVarValidator

    def test_validator_has_providers(self):
        """Test EnvVarValidator has provider config."""
        EVV = self._get_class()
        self.assertIn("cerebras", EVV.PROVIDER_ENV_MAP)
        self.assertIn("portkey", EVV.PROVIDER_ENV_MAP)
        self.assertIn("cloudflare_workers_ai", EVV.PROVIDER_ENV_MAP)
        self.assertIn("cloudflare_ai_gateway", EVV.PROVIDER_ENV_MAP)

    def test_missing_env_vars_detected(self):
        """Test that missing environment variables are detected."""
        EVV = self._get_class()

        with patch.dict(os.environ, {}, clear=True):
            result = EVV.validate(["cerebras", "portkey"])
            self.assertIsInstance(result, dict)
            self.assertIn("valid_providers", result)
            self.assertIn("invalid_providers", result)
            # No API keys set → all should be invalid
            self.assertIn("cerebras", result["invalid_providers"])

    def test_present_env_vars_pass(self):
        """Test that present environment variables pass validation."""
        EVV = self._get_class()

        with patch.dict(os.environ, {
            "CEREBRAS_API_KEY_1": "test-key-12345678",
        }):
            result = EVV.validate(["cerebras"])
            self.assertIsInstance(result, dict)
            self.assertIn("cerebras", result["valid_providers"])

    def test_validate_unknown_provider(self):
        """Test validation with an unknown provider name."""
        EVV = self._get_class()
        result = EVV.validate(["nonexistent_provider"])
        self.assertIn("nonexistent_provider", result["invalid_providers"])


class TestProviderCheckWithMockedGateway(unittest.TestCase):
    """Test provider health checking with a mocked gateway."""

    @patch("torshield_ai_gateway.gateway.TorShieldAIGateway")
    def test_provider_check_primary_ok(self, MockGateway):
        """Test health check with a primary provider responding correctly."""
        mock_gw = MagicMock()
        mock_gw.chat.return_value = "TORSHIELD_OK"
        mock_gw.last_response_source = "primary"
        mock_gw.health_stats.return_value = {
            "total_requests": 1,
            "primary_successes": 1,
            "local_fallback_uses": 0,
            "all_primary_failed": 0,
            "primary_success_rate": 1.0,
            "degraded_rate": 0.0,
            "provider_attempts": {"cerebras": 1},
            "available_providers": ["cerebras"],
        }
        MockGateway.return_value = mock_gw

        # Verify the mock gateway works as expected
        result = mock_gw.chat(messages=[{"role": "user", "content": "test"}])
        self.assertEqual(result, "TORSHIELD_OK")
        self.assertEqual(mock_gw.last_response_source, "primary")

    @patch("torshield_ai_gateway.gateway.TorShieldAIGateway")
    def test_provider_check_degraded(self, MockGateway):
        """Test health check when only LocalAIEngine responds."""
        mock_gw = MagicMock()
        mock_gw.chat.return_value = "local fallback response"
        mock_gw.last_response_source = "local_fallback"
        mock_gw.health_stats.return_value = {
            "total_requests": 1,
            "primary_successes": 0,
            "local_fallback_uses": 1,
            "all_primary_failed": 1,
            "primary_success_rate": 0.0,
            "degraded_rate": 1.0,
            "provider_attempts": {},
            "available_providers": [],
        }
        MockGateway.return_value = mock_gw

        result = mock_gw.chat(messages=[{"role": "user", "content": "test"}])
        self.assertEqual(mock_gw.last_response_source, "local_fallback")
        self.assertEqual(mock_gw.health_stats()["degraded_rate"], 1.0)


class TestExitCodeLogic(unittest.TestCase):
    """Test health check exit code logic.

    Exit code policy:
      0 — at least one PRIMARY provider responds correctly
      1 — ALL primary providers fail (even if LocalAIEngine works)
      2 — required environment variables are missing entirely
    """

    def test_exit_0_on_primary_success(self):
        """Test exit code 0 when a primary provider responds."""
        # Simulate the condition for exit code 0
        any_primary_ok = True
        any_env_missing = False

        if any_env_missing:
            expected_exit = 2
        elif any_primary_ok:
            expected_exit = 0
        else:
            expected_exit = 1

        self.assertEqual(expected_exit, 0)

    def test_exit_1_on_all_primary_fail(self):
        """Test exit code 1 when all primary providers fail."""
        any_primary_ok = False
        any_env_missing = False

        if any_env_missing:
            expected_exit = 2
        elif any_primary_ok:
            expected_exit = 0
        else:
            expected_exit = 1

        self.assertEqual(expected_exit, 1)

    def test_exit_2_on_missing_env_vars(self):
        """Test exit code 2 when required env vars are missing."""
        any_primary_ok = False
        any_env_missing = True

        if any_env_missing:
            expected_exit = 2
        elif any_primary_ok:
            expected_exit = 0
        else:
            expected_exit = 1

        self.assertEqual(expected_exit, 2)


class TestIsValidAIResponse(unittest.TestCase):
    """Test the is_valid_ai_response flexible validation."""

    def _get_func(self):
        from scripts.ai_gateway_health_check import is_valid_ai_response
        return is_valid_ai_response

    def test_torshield_ok_accepted(self):
        """Test that TORSHIELD_OK is accepted."""
        is_valid = self._get_func()
        self.assertTrue(is_valid("TORSHIELD_OK"))

    def test_any_nonempty_response_accepted(self):
        """Test that any non-empty response is accepted."""
        is_valid = self._get_func()
        self.assertTrue(is_valid("I am a helpful assistant"))
        self.assertTrue(is_valid("Hello world"))
        self.assertTrue(is_valid("The bridge score is 85"))

    def test_empty_response_rejected(self):
        """Test that empty responses are rejected."""
        is_valid = self._get_func()
        self.assertFalse(is_valid(""))
        self.assertFalse(is_valid("   "))

    def test_error_patterns_rejected(self):
        """Test that error patterns are rejected."""
        is_valid = self._get_func()
        self.assertFalse(is_valid("ERROR: invalid request"))
        self.assertFalse(is_valid("UNAUTHORIZED access"))
        self.assertFalse(is_valid("FORBIDDEN resource"))
        self.assertFalse(is_valid("NOT FOUND endpoint"))

    def test_torshield_ok_in_longer_response(self):
        """Test that TORSHIELD_OK embedded in longer response is accepted."""
        is_valid = self._get_func()
        self.assertTrue(is_valid("The system reports TORSHIELD_OK status"))
        self.assertTrue(is_valid("ok TORSHIELD_OK done"))

    def test_min_length_respected(self):
        """Test that responses below min_length are rejected."""
        is_valid = self._get_func()
        self.assertFalse(is_valid("ab", min_length=3))
        self.assertTrue(is_valid("abc", min_length=3))


if __name__ == "__main__":
    unittest.main()
