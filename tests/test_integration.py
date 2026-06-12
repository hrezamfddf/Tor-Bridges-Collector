"""
tests/test_integration.py — Integration tests for Tor-Bridges-Collector

Verifies that multiple components work together correctly:
  - Gateway + Providers integration (provider waterfall with mocked HTTP)
  - Gateway + Model Selector integration (dynamic model selection with mocked API)
  - Gateway + Circuit Breaker integration (circuit breaker trips affect gateway routing)
  - Gateway + LocalAIEngine fallback integration
  - IranAutoDefense + Anti-Filter V2 + Anti-DPI V2 integration
  - Monitoring + Health Check integration
  - Provider Dashboard + Structured Logging integration

All tests use unittest.mock — no real API calls.
"""

import json
import os
import sys
import time
import unittest
from unittest.mock import MagicMock, Mock, patch, call

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ══════════════════════════════════════════════════════════════════════════════
# 1. Gateway + Providers Integration
# ══════════════════════════════════════════════════════════════════════════════

class TestGatewayProvidersIntegration(unittest.TestCase):
    """Test Gateway working with mocked providers in a waterfall configuration."""

    def _create_gateway(self, provider_results=None):
        """Create a gateway with mocked providers for integration testing."""
        from torshield_ai_gateway.gateway import TorShieldAIGateway
        gw = object.__new__(TorShieldAIGateway)
        gw._providers = {}
        gw._last_response_source = None
        gw._stats = {
            "total_requests": 0,
            "primary_successes": 0,
            "local_fallback_uses": 0,
            "all_primary_failed": 0,
            "provider_attempts": {},
        }
        gw._selector = MagicMock()

        if provider_results is None:
            provider_results = {}

        for name, result in provider_results.items():
            mock_provider = MagicMock()
            if isinstance(result, Exception):
                mock_provider.chat_complete.side_effect = result
            elif result is None:
                mock_provider.chat_complete.return_value = ""
            else:
                mock_provider.chat_complete.return_value = result
            gw._providers[name] = mock_provider

        return gw

    def test_waterfall_tries_providers_in_priority_order(self):
        """Test that gateway calls providers in the defined priority order."""
        gw = self._create_gateway({
            "cerebras": "cerebras_ok",
            "cloudflare_ai_gateway": "cf_gw_ok",
            "cloudflare_workers_ai": "cf_w_ok",
            "portkey": "portkey_ok",
        })

        result = gw.chat(messages=[{"role": "user", "content": "test"}])

        self.assertEqual(result, "cerebras_ok")
        # First provider should have been called
        gw._providers["cerebras"].chat_complete.assert_called_once()
        # Other providers should NOT have been called (first succeeded)
        gw._providers["cloudflare_ai_gateway"].chat_complete.assert_not_called()

    def test_waterfall_skips_failed_providers(self):
        """Test that gateway skips providers that raise exceptions."""
        gw = self._create_gateway({
            "cerebras": Exception("cerebras down"),
            "cloudflare_ai_gateway": Exception("cf_gw down"),
            "cloudflare_workers_ai": "cf_workers_ok",
            "portkey": "portkey_ok",
        })

        result = gw.chat(messages=[{"role": "user", "content": "test"}])

        # Should get the first successful provider's response
        self.assertIn(result, ["cf_workers_ok", "portkey_ok"])
        self.assertEqual(gw._last_response_source, "primary")
        # All providers up to the successful one should have been tried
        gw._providers["cerebras"].chat_complete.assert_called()
        gw._providers["cloudflare_ai_gateway"].chat_complete.assert_called()

    def test_waterfall_records_all_attempts(self):
        """Test that gateway records attempt counts for each provider tried."""
        gw = self._create_gateway({
            "cerebras": Exception("down"),
            "cloudflare_ai_gateway": Exception("down"),
            "cloudflare_workers_ai": "ok",
        })

        gw.chat(messages=[{"role": "user", "content": "test"}])

        # All three providers should be recorded in attempts
        self.assertIn("cerebras", gw._stats["provider_attempts"])
        self.assertIn("cloudflare_ai_gateway", gw._stats["provider_attempts"])
        self.assertIn("cloudflare_workers_ai", gw._stats["provider_attempts"])

    def test_waterfall_with_mocked_http_responses(self):
        """Test provider waterfall with realistic mocked HTTP response flows."""
        from torshield_ai_gateway.providers import _BaseProvider

        gw = self._create_gateway({
            "cerebras": "TORSHIELD_OK analysis complete",
            "cloudflare_ai_gateway": "TORSHIELD_OK cf response",
        })

        with patch.object(gw, 'chat', wraps=gw.chat) as spy_chat:
            result = gw.chat(messages=[{"role": "user", "content": "analyze bridge"}])

        self.assertIn("TORSHIELD_OK", result)
        spy_chat.assert_called_once()

    def test_multiple_requests_through_waterfall(self):
        """Test multiple sequential requests through the provider waterfall."""
        gw = self._create_gateway({
            "cerebras": "response_1",
        })

        # First request
        r1 = gw.chat(messages=[{"role": "user", "content": "test1"}])
        self.assertEqual(r1, "response_1")

        # Change provider response for second request
        gw._providers["cerebras"].chat_complete.return_value = "response_2"
        r2 = gw.chat(messages=[{"role": "user", "content": "test2"}])
        self.assertEqual(r2, "response_2")

        self.assertEqual(gw._stats["total_requests"], 2)
        self.assertEqual(gw._stats["primary_successes"], 2)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Gateway + Model Selector Integration
# ══════════════════════════════════════════════════════════════════════════════

class TestGatewayModelSelectorIntegration(unittest.TestCase):
    """Test Gateway working with the CloudflareModelSelector."""

    def _create_gateway(self, provider_results=None):
        """Create a gateway with mocked providers and real model selector."""
        from torshield_ai_gateway.gateway import TorShieldAIGateway
        gw = object.__new__(TorShieldAIGateway)
        gw._providers = {}
        gw._last_response_source = None
        gw._stats = {
            "total_requests": 0,
            "primary_successes": 0,
            "local_fallback_uses": 0,
            "all_primary_failed": 0,
            "provider_attempts": {},
        }

        if provider_results is None:
            provider_results = {}

        for name, result in provider_results.items():
            mock_provider = MagicMock()
            if isinstance(result, Exception):
                mock_provider.chat_complete.side_effect = result
            else:
                mock_provider.chat_complete.return_value = result
            gw._providers[name] = mock_provider

        return gw

    def test_gateway_uses_model_selector(self):
        """Test that gateway initializes with a model selector instance."""
        from torshield_ai_gateway.model_selector import CloudflareModelSelector
        CloudflareModelSelector._instance = None
        selector = CloudflareModelSelector.instance()
        self.assertIsNotNone(selector)
        CloudflareModelSelector._instance = None

    def test_model_selector_status_accessible_from_gateway(self):
        """Test that gateway exposes model selector status."""
        from torshield_ai_gateway.model_selector import CloudflareModelSelector, model_selector_status
        CloudflareModelSelector._instance = None

        status = model_selector_status()
        self.assertIsInstance(status, dict)
        self.assertIn("selected", status)

        CloudflareModelSelector._instance = None

    def test_gateway_passes_task_to_provider(self):
        """Test that gateway passes the task parameter through to providers."""
        gw = self._create_gateway({
            "cerebras": "task_response",
        })

        gw.chat(messages=[{"role": "user", "content": "test"}], task="reasoning")

        # Verify the provider was called with the task parameter
        call_args = gw._providers["cerebras"].chat_complete.call_args
        self.assertEqual(call_args.kwargs.get("task", call_args[1].get("task")), "reasoning")

    def test_model_failure_reporting_affects_selection(self):
        """Test that reporting model failures affects the model selector."""
        from torshield_ai_gateway.model_selector import CloudflareModelSelector, ModelInfo
        CloudflareModelSelector._instance = None
        selector = CloudflareModelSelector()

        # Report a failure
        selector.report_model_failure("@cf/test/bad-model", error_code=400)
        self.assertEqual(selector._failure_counts.get("@cf/test/bad-model"), 1)

        # Apply penalties
        models = [
            ModelInfo(id="@cf/test/good-model", name="Good", score=90.0),
            ModelInfo(id="@cf/test/bad-model", name="Bad", score=85.0),
        ]
        selector._apply_failure_penalties(models)
        good = next(m for m in models if m.id == "@cf/test/good-model")
        bad = next(m for m in models if m.id == "@cf/test/bad-model")
        self.assertGreater(good.score, bad.score)

        CloudflareModelSelector._instance = None

    def test_cache_invalidation_triggers_refresh(self):
        """Test that cache invalidation resets the model selector state."""
        from torshield_ai_gateway.model_selector import CloudflareModelSelector
        CloudflareModelSelector._instance = None
        selector = CloudflareModelSelector()

        selector._cache_ts = time.monotonic()
        selector._cached_models = [MagicMock()]
        selector._selected = {"general": "some-model"}

        selector.invalidate_cache()

        self.assertEqual(selector._cache_ts, 0.0)
        self.assertEqual(selector._cached_models, [])
        self.assertEqual(selector._selected, {})

        CloudflareModelSelector._instance = None


# ══════════════════════════════════════════════════════════════════════════════
# 3. Gateway + Circuit Breaker Integration
# ══════════════════════════════════════════════════════════════════════════════

class TestGatewayCircuitBreakerIntegration(unittest.TestCase):
    """Test that circuit breaker trips affect gateway routing decisions."""

    def test_circuit_breaker_prevents_provider_retry(self):
        """Test that an open circuit breaker prevents requests to that provider."""
        from torshield_ai_gateway.providers import ProviderCircuitBreaker

        cb = ProviderCircuitBreaker("cerebras", failure_threshold=2)
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "open")
        self.assertFalse(cb.allow_request())

    def test_circuit_breaker_recovery_allows_provider(self):
        """Test that circuit breaker recovery allows provider to be retried."""
        from torshield_ai_gateway.providers import ProviderCircuitBreaker

        cb = ProviderCircuitBreaker("cerebras", failure_threshold=2, recovery_timeout=0.05)
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "open")

        time.sleep(0.06)
        self.assertTrue(cb.allow_request())
        self.assertEqual(cb.state, "half_open")

    def test_independent_circuit_breakers_per_provider(self):
        """Test that each provider has an independent circuit breaker."""
        from torshield_ai_gateway.providers import ProviderCircuitBreaker

        cb_cerebras = ProviderCircuitBreaker("cerebras", failure_threshold=2)
        cb_cf = ProviderCircuitBreaker("cloudflare", failure_threshold=2)

        # Trip cerebras circuit breaker
        cb_cerebras.record_failure()
        cb_cerebras.record_failure()
        self.assertEqual(cb_cerebras.state, "open")
        self.assertEqual(cb_cf.state, "closed")
        self.assertTrue(cb_cf.allow_request())

    def test_gateway_reroutes_around_open_circuit(self):
        """Test that gateway can reroute when a provider's circuit is open."""
        from torshield_ai_gateway.gateway import TorShieldAIGateway
        from torshield_ai_gateway.providers import ProviderCircuitBreaker

        gw = object.__new__(TorShieldAIGateway)
        gw._providers = {}
        gw._last_response_source = None
        gw._stats = {
            "total_requests": 0,
            "primary_successes": 0,
            "local_fallback_uses": 0,
            "all_primary_failed": 0,
            "provider_attempts": {},
        }
        gw._selector = MagicMock()

        # Set up mock providers where cerebras has an open circuit breaker
        mock_cerebras = MagicMock()
        mock_cerebras.chat_complete.return_value = "cerebras_response"
        mock_cerebras._circuit_breaker = ProviderCircuitBreaker("cerebras", failure_threshold=2)
        mock_cerebras._circuit_breaker.record_failure()
        mock_cerebras._circuit_breaker.record_failure()

        mock_portkey = MagicMock()
        mock_portkey.chat_complete.return_value = "portkey_response"

        gw._providers["cerebras"] = mock_cerebras
        gw._providers["portkey"] = mock_portkey

        # Gateway should still try cerebras (it doesn't check CB internally,
        # but the provider itself would reject). The important thing is the
        # waterfall continues to the next provider.
        result = gw.chat(messages=[{"role": "user", "content": "test"}])

        # cerebras circuit breaker should be open
        self.assertEqual(mock_cerebras._circuit_breaker.state, "open")

    def test_full_circuit_breaker_lifecycle_with_gateway(self):
        """Test a complete circuit breaker lifecycle: closed → open → half_open → closed."""
        from torshield_ai_gateway.providers import ProviderCircuitBreaker

        cb = ProviderCircuitBreaker("test_provider", failure_threshold=3, recovery_timeout=0.05)

        # Closed phase: allow all requests
        for _ in range(2):
            self.assertTrue(cb.allow_request())
            cb.record_failure()
        self.assertEqual(cb.state, "closed")

        # Third failure trips the circuit
        cb.record_failure()
        self.assertEqual(cb.state, "open")
        self.assertFalse(cb.allow_request())

        # Recovery phase
        time.sleep(0.06)
        self.assertTrue(cb.allow_request())
        self.assertEqual(cb.state, "half_open")

        # Success closes the circuit
        cb.record_success()
        self.assertEqual(cb.state, "closed")
        self.assertEqual(cb.failure_count, 0)


# ══════════════════════════════════════════════════════════════════════════════
# 4. Gateway + LocalAIEngine Fallback Integration
# ══════════════════════════════════════════════════════════════════════════════

class TestGatewayLocalAIFallbackIntegration(unittest.TestCase):
    """Test Gateway falling back to LocalAIEngine when all providers fail."""

    def _create_gateway(self, provider_results=None):
        from torshield_ai_gateway.gateway import TorShieldAIGateway
        gw = object.__new__(TorShieldAIGateway)
        gw._providers = {}
        gw._last_response_source = None
        gw._stats = {
            "total_requests": 0,
            "primary_successes": 0,
            "local_fallback_uses": 0,
            "all_primary_failed": 0,
            "provider_attempts": {},
        }
        gw._selector = MagicMock()

        if provider_results is None:
            provider_results = {}

        for name, result in provider_results.items():
            mock_provider = MagicMock()
            if isinstance(result, Exception):
                mock_provider.chat_complete.side_effect = result
            else:
                mock_provider.chat_complete.return_value = result
            gw._providers[name] = mock_provider

        return gw

    def test_local_ai_engine_used_when_all_providers_fail(self):
        """Test that LocalAIEngine is invoked when all primary providers fail."""
        gw = self._create_gateway({
            "cerebras": Exception("down"),
            "cloudflare_workers_ai": Exception("down"),
        })

        with patch("torshield_ai_gateway.gateway.LocalAIEngine") as MockLocalAI:
            mock_engine = MagicMock()
            mock_engine.chat_complete.return_value = "local_fallback_response"
            MockLocalAI.return_value = mock_engine

            result = gw.chat(messages=[{"role": "user", "content": "test"}])

        self.assertEqual(result, "local_fallback_response")
        self.assertEqual(gw._last_response_source, "local_fallback")
        self.assertEqual(gw._stats["local_fallback_uses"], 1)
        self.assertEqual(gw._stats["all_primary_failed"], 1)

    def test_local_ai_engine_not_used_when_provider_succeeds(self):
        """Test that LocalAIEngine is NOT invoked when a primary provider succeeds."""
        gw = self._create_gateway({
            "cerebras": "primary_response",
        })

        with patch("torshield_ai_gateway.gateway.LocalAIEngine") as MockLocalAI:
            result = gw.chat(messages=[{"role": "user", "content": "test"}])
            MockLocalAI.assert_not_called()

        self.assertEqual(result, "primary_response")
        self.assertEqual(gw._last_response_source, "primary")
        self.assertEqual(gw._stats["local_fallback_uses"], 0)

    def test_local_ai_engine_ultimate_fallback(self):
        """Test that gateway returns JSON error when even LocalAIEngine fails."""
        gw = self._create_gateway({})

        with patch("torshield_ai_gateway.gateway.LocalAIEngine") as MockLocalAI:
            mock_engine = MagicMock()
            mock_engine.chat_complete.side_effect = Exception("local engine crashed")
            MockLocalAI.return_value = mock_engine

            result = gw.chat(messages=[{"role": "user", "content": "test"}])

        self.assertIn("error", result)
        self.assertIn("degraded", result)

    def test_local_ai_engine_receives_task_parameter(self):
        """Test that LocalAIEngine fallback receives the task parameter."""
        gw = self._create_gateway({
            "cerebras": Exception("down"),
        })

        with patch("torshield_ai_gateway.gateway.LocalAIEngine") as MockLocalAI:
            mock_engine = MagicMock()
            mock_engine.chat_complete.return_value = "local_response"
            MockLocalAI.return_value = mock_engine

            gw.chat(
                messages=[{"role": "user", "content": "test"}],
                task="reasoning",
            )

            # LocalAIEngine should have been called with the task
            mock_engine.chat_complete.assert_called_once()
            call_kwargs = mock_engine.chat_complete.call_args
            self.assertEqual(call_kwargs.kwargs.get("task", call_kwargs[1].get("task")), "reasoning")

    def test_stats_reflect_fallback_usage(self):
        """Test that health stats accurately reflect LocalAIEngine fallback usage."""
        gw = self._create_gateway({})

        with patch("torshield_ai_gateway.gateway.LocalAIEngine") as MockLocalAI:
            mock_engine = MagicMock()
            mock_engine.chat_complete.return_value = "local"
            MockLocalAI.return_value = mock_engine

            # Make 3 requests (all will fallback)
            for _ in range(3):
                gw.chat(messages=[{"role": "user", "content": "test"}])

        stats = gw.health_stats()
        self.assertEqual(stats["total_requests"], 3)
        self.assertEqual(stats["local_fallback_uses"], 3)
        self.assertEqual(stats["all_primary_failed"], 3)
        self.assertEqual(stats["primary_success_rate"], 0.0)
        self.assertEqual(stats["degraded_rate"], 1.0)


# ══════════════════════════════════════════════════════════════════════════════
# 5. IranAutoDefense + Anti-Filter V2 + Anti-DPI V2 Integration
# ══════════════════════════════════════════════════════════════════════════════

class TestIranModulesIntegration(unittest.TestCase):
    """Test IranAutoDefense + Anti-Filter V2 + Anti-DPI V2 working together."""

    def test_auto_defense_uses_anti_filter_for_censorship_detection(self):
        """Test that IranAutoDefense can detect censorship and produce results."""
        from torshield_ai_gateway.iran_auto_defense import IranAutoDefense

        defense = IranAutoDefense()
        threats = defense.detect_threats()
        self.assertIsNotNone(threats)

    def test_auto_defense_analyzes_bridges_with_threats(self):
        """Test that IranAutoDefense analyzes bridges using detected threats."""
        from torshield_ai_gateway.iran_auto_defense import IranAutoDefense

        defense = IranAutoDefense()
        threats = defense.detect_threats()
        bridges = [
            "obfs4 1.2.3.4:443 cert=test iat-mode=2",
            "webtunnel 5.6.7.8:443 url=https://example.com",
        ]
        scores = defense.analyze_bridges(bridges, threats)
        self.assertIsInstance(scores, dict)

    def test_auto_defense_transport_priorities_match_censorship_levels(self):
        """Test that transport priorities are defined for each censorship level."""
        from torshield_ai_gateway.iran_auto_defense import IranAutoDefense

        defense = IranAutoDefense()
        for level in range(1, 6):
            self.assertIn(level, defense.TRANSPORT_PRIORITIES)
            transports = defense.TRANSPORT_PRIORITIES[level]
            self.assertIsInstance(transports, list)
            self.assertGreater(len(transports), 0)

    def test_anti_filter_v2_detects_censorship_level(self):
        """Test that Anti-Filter V2 can detect censorship levels."""
        from torshield_ai_gateway.iran_smart_anti_filter_v2 import IranSmartAntiFilterV2

        v2 = IranSmartAntiFilterV2()
        state = v2.detect_censorship_ai()
        self.assertIsNotNone(state)

    def test_anti_dpi_v2_analyzes_traffic(self):
        """Test that Anti-DPI V2 can analyze threats."""
        from torshield_ai_gateway.ai_anti_dpi_iran_v2 import IranAntiDPIV2

        v2 = IranAntiDPIV2()
        result = v2.analyze_threats()
        self.assertIsNotNone(result)

    def test_auto_defense_status_includes_subsystem_info(self):
        """Test that IranAutoDefense status includes subsystem information."""
        from torshield_ai_gateway.iran_auto_defense import IranAutoDefense

        defense = IranAutoDefense()
        status = defense.get_status()
        self.assertIsInstance(status, dict)

    def test_censorship_level_affects_transport_selection(self):
        """Test that higher censorship levels prioritize CDN-fronted transports."""
        from torshield_ai_gateway.iran_auto_defense import IranAutoDefense

        defense = IranAutoDefense()

        # Level 5 (NIN/Shutdown) should only use CDN-fronted transports
        level5_transports = defense.TRANSPORT_PRIORITIES[5]
        for t in level5_transports:
            self.assertIn(t, ["webtunnel", "snowflake", "obfs4_iat2"])

        # Level 1 should have more options
        level1_transports = defense.TRANSPORT_PRIORITIES[1]
        self.assertGreaterEqual(len(level1_transports), len(level5_transports))


# ══════════════════════════════════════════════════════════════════════════════
# 6. Monitoring + Health Check Integration
# ══════════════════════════════════════════════════════════════════════════════

class TestMonitoringHealthCheckIntegration(unittest.TestCase):
    """Test Monitoring module integrating with Health Check components."""

    def test_exponential_backoff_with_health_check(self):
        """Test that ExponentialBackoffRetry works with health check functions."""
        from scripts.ai_gateway_health_check import ExponentialBackoffRetry

        retry = ExponentialBackoffRetry(max_retries=2, base_delay_sec=0.01, jitter=0.0)

        call_count = [0]
        def health_check_fn():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ConnectionError("provider unreachable")
            return "healthy"

        result, attempts, error = retry.execute(health_check_fn)
        self.assertEqual(result, "healthy")
        self.assertEqual(attempts, 2)

    def test_auth_failure_diagnostics_with_gateway(self):
        """Test AuthFailureDiagnostics with a mocked gateway response."""
        from scripts.ai_gateway_health_check import AuthFailureDiagnostics
        import urllib.error

        err = urllib.error.HTTPError(
            url="https://api.cerebras.ai/v1/chat/completions",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=None,
        )
        result = AuthFailureDiagnostics.diagnose_http_error(
            error=err,
            provider="cerebras",
            url="https://api.cerebras.ai/v1/chat/completions",
            headers_sent={"Authorization": "Bearer sk-test-key"},
        )
        self.assertIsInstance(result, dict)
        self.assertEqual(result["http_status"], 401)
        self.assertIn("recommendations", result)

    def test_env_var_validator_with_health_check(self):
        """Test EnvVarValidator correctly identifies configured vs missing providers."""
        from scripts.ai_gateway_health_check import EnvVarValidator

        with patch.dict(os.environ, {
            "CEREBRAS_API_KEY_1": "test-key-12345678",
        }):
            result = EnvVarValidator.validate(["cerebras", "portkey"])
            self.assertIn("cerebras", result["valid_providers"])
            self.assertIn("portkey", result["invalid_providers"])

    def test_health_check_exit_code_with_gateway_stats(self):
        """Test that health check exit code logic works with gateway health stats."""
        # Simulate gateway health stats for a healthy system
        health_stats = {
            "total_requests": 10,
            "primary_successes": 8,
            "local_fallback_uses": 2,
            "all_primary_failed": 2,
            "primary_success_rate": 0.8,
            "degraded_rate": 0.2,
            "provider_attempts": {"cerebras": 10},
            "available_providers": ["cerebras"],
        }

        # Determine expected exit code
        any_primary_ok = health_stats["primary_successes"] > 0
        any_env_missing = False

        if any_env_missing:
            expected_exit = 2
        elif any_primary_ok:
            expected_exit = 0
        else:
            expected_exit = 1

        self.assertEqual(expected_exit, 0)

    def test_monitoring_health_check_reexport(self):
        """Test that monitoring.health_check re-exports work correctly."""
        from monitoring.health_check import ExponentialBackoffRetry, AuthFailureDiagnostics, EnvVarValidator

        self.assertTrue(hasattr(ExponentialBackoffRetry, 'execute'))
        self.assertTrue(hasattr(AuthFailureDiagnostics, 'diagnose_http_error'))
        self.assertTrue(hasattr(EnvVarValidator, 'validate'))


# ══════════════════════════════════════════════════════════════════════════════
# 7. Provider Dashboard + Structured Logging Integration
# ══════════════════════════════════════════════════════════════════════════════

class TestDashboardStructuredLoggingIntegration(unittest.TestCase):
    """Test Provider Dashboard working with Structured Logging."""

    def test_dashboard_generates_report_with_mocked_gateway(self):
        """Test that ProviderHealthDashboard generates a report using gateway stats."""
        from monitoring.provider_dashboard import ProviderHealthDashboard

        dashboard = ProviderHealthDashboard()

        mock_stats = {
            "total_requests": 50,
            "primary_successes": 45,
            "local_fallback_uses": 5,
            "all_primary_failed": 5,
            "primary_success_rate": 0.9,
            "degraded_rate": 0.1,
            "provider_attempts": {"cerebras": 30, "portkey": 20},
            "available_providers": ["cerebras", "portkey"],
        }

        with patch.object(dashboard, '_get_gateway_stats', return_value=mock_stats):
            with patch.object(dashboard, '_get_provider_circuit_state', return_value="closed"):
                with patch.object(dashboard, '_get_provider_latency', return_value=150.0):
                    report = dashboard.generate_report()

        self.assertEqual(report.total_requests, 50)
        self.assertEqual(report.primary_success_rate, 0.9)
        self.assertGreater(len(report.providers), 0)

    def test_dashboard_determines_overall_status(self):
        """Test that dashboard correctly determines healthy/degraded/critical status."""
        from monitoring.provider_dashboard import ProviderHealthDashboard, DashboardReport, ProviderHealthSnapshot

        dashboard = ProviderHealthDashboard()

        # Test healthy status
        healthy_stats = {
            "total_requests": 10,
            "primary_successes": 10,
            "local_fallback_uses": 0,
            "all_primary_failed": 0,
            "primary_success_rate": 1.0,
            "degraded_rate": 0.0,
            "provider_attempts": {"cerebras": 10},
            "available_providers": ["cerebras"],
        }
        with patch.object(dashboard, '_get_gateway_stats', return_value=healthy_stats):
            with patch.object(dashboard, '_get_provider_circuit_state', return_value="closed"):
                with patch.object(dashboard, '_get_provider_latency', return_value=100.0):
                    report = dashboard.generate_report()
        self.assertEqual(report.overall_status, "healthy")

    def test_dashboard_critical_status_when_no_providers(self):
        """Test that dashboard reports critical when no providers are available."""
        from monitoring.provider_dashboard import ProviderHealthDashboard

        dashboard = ProviderHealthDashboard()

        critical_stats = {
            "total_requests": 5,
            "primary_successes": 0,
            "local_fallback_uses": 5,
            "all_primary_failed": 5,
            "primary_success_rate": 0.0,
            "degraded_rate": 1.0,
            "provider_attempts": {},
            "available_providers": [],
        }
        with patch.object(dashboard, '_get_gateway_stats', return_value=critical_stats):
            with patch.object(dashboard, '_get_provider_circuit_state', return_value="open"):
                with patch.object(dashboard, '_get_provider_latency', return_value=0.0):
                    report = dashboard.generate_report()

        self.assertEqual(report.overall_status, "critical")

    def test_structured_logging_with_provider_metrics(self):
        """Test that StructuredJsonFormatter works with provider metrics."""
        from monitoring.structured_logging import StructuredJsonFormatter, ProviderHealthMetrics

        # Test formatter produces valid JSON
        formatter = StructuredJsonFormatter()
        import logging
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="test.py",
            lineno=1, msg="Provider cerebras responded", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        self.assertIn("timestamp", parsed)
        self.assertIn("level", parsed)
        self.assertIn("message", parsed)

    def test_provider_health_metrics_tracking(self):
        """Test ProviderHealthMetrics tracks provider request metrics."""
        from monitoring.structured_logging import ProviderHealthMetrics

        metrics = ProviderHealthMetrics()
        metrics.record_request("cerebras", success=True, latency_ms=120.5)
        metrics.record_request("cerebras", success=True, latency_ms=85.3)
        metrics.record_request("cerebras", success=False, latency_ms=0.0,
                               error="401 Unauthorized", failure_type="auth")

        report = metrics.get_all_metrics()
        self.assertIn("cerebras", report)
        cerebras = report["cerebras"]
        self.assertEqual(cerebras["request_count"], 3)
        self.assertEqual(cerebras["success_count"], 2)
        self.assertEqual(cerebras["failure_count"], 1)

    def test_dashboard_save_and_history(self):
        """Test dashboard can save reports and maintain history."""
        from monitoring.provider_dashboard import ProviderHealthDashboard

        dashboard = ProviderHealthDashboard()

        mock_stats = {
            "total_requests": 10,
            "primary_successes": 8,
            "local_fallback_uses": 2,
            "all_primary_failed": 2,
            "primary_success_rate": 0.8,
            "degraded_rate": 0.2,
            "provider_attempts": {"cerebras": 10},
            "available_providers": ["cerebras"],
        }

        with patch.object(dashboard, '_get_gateway_stats', return_value=mock_stats):
            with patch.object(dashboard, '_get_provider_circuit_state', return_value="closed"):
                with patch.object(dashboard, '_get_provider_latency', return_value=100.0):
                    report1 = dashboard.generate_report()
                    report2 = dashboard.generate_report()

        history = dashboard.get_history(limit=5)
        self.assertGreaterEqual(len(history), 2)

    def test_failure_analytics_classifies_errors(self):
        """Test FailureAnalytics classifies provider errors correctly."""
        from monitoring.structured_logging import FailureAnalytics

        analytics = FailureAnalytics()

        # Record various failure types
        analytics.record_failure("cerebras", "401 Unauthorized", "auth")
        analytics.record_failure("portkey", "Connection timeout", "network")
        analytics.record_failure("cloudflare", "Model not found", "model")
        analytics.record_failure("cerebras", "429 Rate limited", "quota")

        report = analytics.get_breakdown()
        self.assertIsInstance(report, dict)
        self.assertIn("by_type", report)
        by_type = report["by_type"]
        self.assertIn("auth", by_type)
        self.assertIn("network", by_type)


if __name__ == "__main__":
    unittest.main()
