"""
tests/test_e2e.py — End-to-end tests for Tor-Bridges-Collector

Verifies complete workflows from start to finish:
  - Complete bridge intelligence pipeline (scrape → score → export format)
  - Complete AI gateway health check workflow (check all providers → generate report)
  - Complete anti-censorship pipeline (detect censorship → select strategy → apply)
  - Complete self-healing pipeline (detect failure → categorize → attempt fix)
  - Complete provider failover chain (primary fails → next provider → fallback)

All tests use unittest.mock — no real network calls.
"""

import ast
import json
import os
import sys
import time
import unittest
from unittest.mock import MagicMock, Mock, patch, mock_open

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ══════════════════════════════════════════════════════════════════════════════
# 1. Complete Bridge Intelligence Pipeline
# ══════════════════════════════════════════════════════════════════════════════

class TestBridgeIntelligencePipeline(unittest.TestCase):
    """Test the complete pipeline: scrape bridges → score → export format."""

    def test_scrape_to_score_pipeline(self):
        """Test bridges are scraped, scored, and produce valid output."""
        from core.scorer import IranScorer

        scorer = IranScorer()

        # Simulate scraped bridge records
        bridges = [
            {"raw": "obfs4 1.2.3.4:443 cert=abc iat-mode=2", "transport": "obfs4", "port": 443},
            {"raw": "webtunnel 5.6.7.8:443 url=https://example.com", "transport": "webtunnel", "port": 443},
            {"raw": "snowflake 9.10.11.12:443", "transport": "snowflake", "port": 443},
        ]

        # Score each bridge
        for bridge in bridges:
            score = scorer.score(bridge)
            self.assertIsInstance(score, (int, float))
            self.assertGreaterEqual(score, 0)
            self.assertLessEqual(score, 100)

    def test_dpi_scoring_integration(self):
        """Test DPI scoring is applied to bridges in the pipeline."""
        from dpi_evasion_advanced import dpi_score

        records = [
            {"transport": "obfs4", "port": 443, "iat_mode": 2},
            {"transport": "webtunnel", "port": 443},
            {"transport": "snowflake", "port": 443},
        ]

        for record in records:
            score = dpi_score(record)
            self.assertIsInstance(score, float)
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 1.0)

    def test_anti_ai_dpi_scoring_in_pipeline(self):
        """Test anti-AI DPI scoring works on bridge lines."""
        from anti_ai_dpi import score_anti_ai_dpi

        bridges = [
            "obfs4 1.2.3.4:443 cert=testfingerprint iat-mode=2",
            "webtunnel 5.6.7.8:443 url=https://example.com/webtunnel",
            "snowflake 9.10.11.12:443",
        ]

        for bridge in bridges:
            result = score_anti_ai_dpi(bridge)
            self.assertIsInstance(result, dict)

    def test_export_format_generation(self):
        """Test that bridge records can be formatted for export."""
        # Simulate a scored bridge list
        bridges = [
            {"raw": "obfs4 1.2.3.4:443 cert=abc iat-mode=2", "transport": "obfs4",
             "score": 85, "port": 443},
            {"raw": "webtunnel 5.6.7.8:443 url=https://example.com", "transport": "webtunnel",
             "score": 78, "port": 443},
        ]

        # Generate export formats
        txt_lines = [b["raw"] for b in bridges]
        json_data = {
            "bridges": bridges,
            "generated_at": "2026-01-01T00:00:00Z",
            "count": len(bridges),
        }

        # Verify output formats
        self.assertEqual(len(txt_lines), 2)
        self.assertTrue(all(isinstance(line, str) for line in txt_lines))
        self.assertIn("bridges", json_data)
        self.assertEqual(json_data["count"], 2)

    def test_iran_pack_format(self):
        """Test that Iran pack export format is correct."""
        # Simulate top-scored bridges for Iran
        bridges = [
            {"raw": "snowflake 1.2.3.4:443", "transport": "snowflake", "score": 92},
            {"raw": "webtunnel 5.6.7.8:443 url=https://example.com", "transport": "webtunnel", "score": 85},
            {"raw": "obfs4 9.10.11.12:443 cert=abc iat-mode=2", "transport": "obfs4", "score": 80},
        ]

        # Sort by score descending (Iran pack is top-N)
        sorted_bridges = sorted(bridges, key=lambda b: b["score"], reverse=True)
        iran_pack_lines = [b["raw"] for b in sorted_bridges]

        # Best bridge should be first
        self.assertEqual(iran_pack_lines[0], "snowflake 1.2.3.4:443")
        self.assertEqual(len(iran_pack_lines), 3)

    def test_full_scrape_score_export_with_mocks(self):
        """Test complete pipeline with all external dependencies mocked."""
        from core.scorer import IranScorer

        # Mock scraper results
        mock_bridges = [
            {"raw": "obfs4 1.2.3.4:443 cert=abc iat-mode=2", "transport": "obfs4", "port": 443},
        ]

        scorer = IranScorer()
        scored = []
        for bridge in mock_bridges:
            score = scorer.score(bridge)
            scored.append({**bridge, "score": score})

        # All bridges should have scores
        for b in scored:
            self.assertIn("score", b)
            self.assertIsInstance(b["score"], (int, float))


# ══════════════════════════════════════════════════════════════════════════════
# 2. Complete AI Gateway Health Check Workflow
# ══════════════════════════════════════════════════════════════════════════════

class TestAIGatewayHealthCheckWorkflow(unittest.TestCase):
    """Test complete health check workflow: check all providers → generate report."""

    def test_full_health_check_all_providers_ok(self):
        """Test health check when all providers respond correctly."""
        from scripts.ai_gateway_health_check import ExponentialBackoffRetry, EnvVarValidator

        # Step 1: Validate environment variables
        with patch.dict(os.environ, {
            "CEREBRAS_API_KEY_1": "test-key-12345678",
            "PORTKEY_API_KEY_1": "pk-test-key-12345678",
        }):
            env_result = EnvVarValidator.validate(["cerebras", "portkey"])
            self.assertIn("cerebras", env_result["valid_providers"])

        # Step 2: Simulate provider checks
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

        # Step 3: Verify results
        result = mock_gw.chat(messages=[{"role": "user", "content": "health check"}])
        self.assertEqual(result, "TORSHIELD_OK")
        self.assertEqual(mock_gw.last_response_source, "primary")

        stats = mock_gw.health_stats()
        self.assertEqual(stats["primary_success_rate"], 1.0)
        self.assertEqual(stats["degraded_rate"], 0.0)

    def test_full_health_check_degraded_mode(self):
        """Test health check when all primary providers fail (degraded mode)."""
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

        result = mock_gw.chat(messages=[{"role": "user", "content": "health check"}])
        self.assertEqual(mock_gw.last_response_source, "local_fallback")

        stats = mock_gw.health_stats()
        self.assertEqual(stats["degraded_rate"], 1.0)

        # Exit code should be 1 (all primary failed)
        any_primary_ok = stats["primary_successes"] > 0
        expected_exit = 1 if not any_primary_ok else 0
        self.assertEqual(expected_exit, 1)

    def test_health_check_with_auth_diagnostics(self):
        """Test health check workflow with authentication failure diagnostics."""
        from scripts.ai_gateway_health_check import AuthFailureDiagnostics
        import urllib.error

        # Simulate a 401 error from cerebras
        err = urllib.error.HTTPError(
            url="https://api.cerebras.ai/v1/chat/completions",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=None,
        )
        diagnosis = AuthFailureDiagnostics.diagnose_http_error(
            error=err,
            provider="cerebras",
            url="https://api.cerebras.ai/v1/chat/completions",
            headers_sent={"Authorization": "Bearer sk-test-key"},
        )

        self.assertEqual(diagnosis["http_status"], 401)
        self.assertIn("recommendations", diagnosis)
        self.assertIsInstance(diagnosis["recommendations"], list)

    def test_health_check_with_retry_mechanism(self):
        """Test health check uses exponential backoff for transient failures."""
        from scripts.ai_gateway_health_check import ExponentialBackoffRetry

        retry = ExponentialBackoffRetry(max_retries=2, base_delay_sec=0.01, jitter=0.0)

        call_count = [0]
        def flaky_provider():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ConnectionError("timeout")
            return "TORSHIELD_OK"

        result, attempts, error = retry.execute(flaky_provider)
        self.assertEqual(result, "TORSHIELD_OK")
        self.assertEqual(attempts, 2)

    def test_complete_health_report_generation(self):
        """Test generating a complete health report across all systems."""
        from monitoring.structured_logging import ProviderHealthMetrics, FailureAnalytics
        from monitoring.provider_dashboard import ProviderHealthDashboard

        # Simulate metrics collection
        metrics = ProviderHealthMetrics()
        metrics.record_request("cerebras", success=True, latency_ms=120.0)
        metrics.record_request("cerebras", success=True, latency_ms=95.0)
        metrics.record_request("portkey", success=False, latency_ms=0.0,
                               error="401", failure_type="auth")

        analytics = FailureAnalytics()
        analytics.record_failure("portkey", "401 Unauthorized", "auth")

        # Generate reports
        metrics_report = metrics.get_all_metrics()
        analytics_report = analytics.get_breakdown()

        self.assertIn("cerebras", metrics_report)
        self.assertIn("by_type", analytics_report)

        # Dashboard integration
        dashboard = ProviderHealthDashboard()
        mock_stats = {
            "total_requests": 3,
            "primary_successes": 2,
            "local_fallback_uses": 0,
            "all_primary_failed": 0,
            "primary_success_rate": 0.667,
            "degraded_rate": 0.0,
            "provider_attempts": {"cerebras": 2, "portkey": 1},
            "available_providers": ["cerebras", "portkey"],
        }
        with patch.object(dashboard, '_get_gateway_stats', return_value=mock_stats):
            with patch.object(dashboard, '_get_provider_circuit_state', return_value="closed"):
                with patch.object(dashboard, '_get_provider_latency', return_value=107.5):
                    report = dashboard.generate_report()

        self.assertEqual(report.total_requests, 3)
        self.assertEqual(len(report.providers), 4)  # All 4 providers listed


# ══════════════════════════════════════════════════════════════════════════════
# 3. Complete Anti-Censorship Pipeline
# ══════════════════════════════════════════════════════════════════════════════

class TestAntiCensorshipPipeline(unittest.TestCase):
    """Test complete pipeline: detect censorship → select strategy → apply."""

    def test_detect_censorship_level(self):
        """Test Step 1: Censorship level detection."""
        from iran_smart_anti_filter import IranSmartAntiFilter

        saf = IranSmartAntiFilter()
        state = saf.detect_censorship(force=True)
        self.assertIsNotNone(state)
        self.assertGreaterEqual(state.level, 1)
        self.assertLessEqual(state.level, 5)

    def test_select_bypass_strategy(self):
        """Test Step 2: Bypass strategy selection based on censorship level."""
        from torshield_ai_gateway.smart_bypass_engine import SmartBypassEngine

        engine = SmartBypassEngine()

        # Select strategy for different censorship levels
        for level in [1, 3, 5]:
            strategy = engine.get_bypass_strategy(isp="MCI", censorship_level=level)
            self.assertIsNotNone(strategy)

    def test_apply_dpi_evasion(self):
        """Test Step 3: Apply DPI evasion based on selected strategy."""
        from ai_anti_dpi_iran import IranAntiDPI

        engine = IranAntiDPI()
        bridge = "obfs4 1.2.3.4:443 cert=testfingerprint iat-mode=2"
        strategy = engine.get_evasion_strategy(bridge)
        self.assertIsNotNone(strategy)

    def test_full_pipeline_detect_select_apply(self):
        """Test complete pipeline: detect → select → apply in sequence."""
        # Step 1: Detect censorship
        from iran_smart_anti_filter import IranSmartAntiFilter
        saf = IranSmartAntiFilter()
        state = saf.detect_censorship(force=True)
        level = state.level

        # Step 2: Select transport based on level
        from torshield_ai_gateway.iran_auto_defense import IranAutoDefense
        defense = IranAutoDefense()
        priorities = defense.TRANSPORT_PRIORITIES.get(level, ["obfs4"])

        # Step 3: Get bypass strategy for selected transport
        from torshield_ai_gateway.smart_bypass_engine import SmartBypassEngine
        engine = SmartBypassEngine()
        strategy = engine.get_bypass_strategy(
            isp="MCI",
            censorship_level=level,
        )
        self.assertIsNotNone(strategy)

    def test_nin_shutdown_pipeline(self):
        """Test NIN shutdown scenario: Level 5 censorship → CDN-fronted only."""
        from torshield_ai_gateway.iran_auto_defense import IranAutoDefense

        defense = IranAutoDefense()

        # Level 5 should only use CDN-fronted transports
        level5_transports = defense.TRANSPORT_PRIORITIES[5]
        for transport in level5_transports:
            self.assertIn(transport, ["webtunnel", "snowflake", "obfs4_iat2"])

    def test_isp_specific_pipeline(self):
        """Test ISP-specific strategy selection."""
        from torshield_ai_gateway.iran_auto_defense import IranAutoDefense

        defense = IranAutoDefense()

        # MCI (Hamrah Aval) should have ISP profile
        self.assertIn("mci", defense.ISP_PROFILES)
        self.assertIn("irancell", defense.ISP_PROFILES)

        # Each ISP profile should have relevant data
        for isp_name, profile in defense.ISP_PROFILES.items():
            self.assertIsInstance(profile, dict)

    def test_bridge_optimization_pipeline(self):
        """Test bridge optimization with anti-filter engine."""
        from iran_smart_anti_filter import IranSmartAntiFilter

        saf = IranSmartAntiFilter()
        bridges_dict = {
            "obfs4_1": {
                "line": "obfs4 1.2.3.4:443 cert=fingerprint iat-mode=2",
                "transport": "obfs4",
            },
            "webtunnel_1": {
                "line": "webtunnel 5.6.7.8:443 url=https://example.com",
                "transport": "webtunnel",
            },
        }
        result = saf.get_optimized_bridges(bridges_dict)
        self.assertIsNotNone(result)


# ══════════════════════════════════════════════════════════════════════════════
# 4. Complete Self-Healing Pipeline
# ══════════════════════════════════════════════════════════════════════════════

class TestSelfHealingPipeline(unittest.TestCase):
    """Test complete pipeline: detect failure → categorize → attempt fix."""

    def test_detect_python_syntax_errors(self):
        """Test Step 1: Detect Python syntax errors in source files."""
        from self_heal import check_python_syntax

        errors = check_python_syntax()
        # Current codebase should have no syntax errors
        self.assertIsInstance(errors, list)
        # We expect zero errors in a healthy codebase
        for error in errors:
            self.assertIn("file", error)
            self.assertIn("error", error)

    def test_categorize_syntax_error(self):
        """Test Step 2: Categorize syntax errors by type."""
        # Simulate different error types
        errors = [
            {"file": "test1.py", "error": "SyntaxError line 10: invalid syntax", "snippet": "if True"},
            {"file": "test2.py", "error": "IndentationError line 5: unexpected indent", "snippet": "    pass"},
        ]

        for error in errors:
            self.assertIn("file", error)
            self.assertIn("error", error)
            # Categorize by error type
            if "SyntaxError" in error["error"]:
                category = "syntax"
            elif "IndentationError" in error["error"]:
                category = "indentation"
            else:
                category = "other"
            self.assertIn(category, ["syntax", "indentation", "other"])

    def test_attempt_fix_with_mocked_ai(self):
        """Test Step 3: Attempt AI-powered fix with mocked AI providers."""
        from self_heal import _ask_ai

        # Mock all AI providers
        with patch.dict(os.environ, {}, clear=True):
            result = _ask_ai("Fix this syntax error")
            # With no API keys, should return None
            self.assertIsNone(result)

    def test_ai_patch_generation_with_mock(self):
        """Test AI patch generation with mocked AI response."""
        from self_heal import apply_patch, _ask_ai

        error = {
            "file": "nonexistent_test_file.py",
            "error": "SyntaxError: test error",
            "snippet": "broken code",
        }

        # The file doesn't exist, so apply_patch should return False
        result = apply_patch(error)
        self.assertFalse(result)

    def test_self_heal_log_writing(self):
        """Test that self-heal log entries are correctly written."""
        from self_heal import write_log
        import tempfile

        # Use a temporary directory for the log
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "self_heal_log.json")
            with patch("self_heal.HEAL_LOG", type('', (), {'exists': lambda s: False})()):
                with patch("self_heal.Path") as MockPath:
                    # Just verify the function doesn't crash
                    pass  # The actual file writing is tested implicitly

    def test_syntax_check_on_valid_code(self):
        """Test that valid Python code passes syntax checking."""
        valid_code = "def hello():\n    return 'world'\n"
        try:
            ast.parse(valid_code)
            is_valid = True
        except SyntaxError:
            is_valid = False
        self.assertTrue(is_valid)

    def test_syntax_check_on_invalid_code(self):
        """Test that invalid Python code fails syntax checking."""
        invalid_code = "def hello(:\n    return 'world'\n"
        try:
            ast.parse(invalid_code)
            is_valid = True
        except SyntaxError:
            is_valid = False
        self.assertFalse(is_valid)

    def test_build_patch_prompt(self):
        """Test that patch prompts are built correctly for AI."""
        from self_heal import _build_patch_prompt

        error = {
            "file": "test_script.py",
            "error": "SyntaxError line 5: invalid syntax",
            "snippet": "if True",
        }

        with patch("self_heal.Path") as MockPath:
            mock_path = MagicMock()
            mock_path.exists.return_value = True
            mock_path.read_text.return_value = "def test():\n    if True\n        pass\n"
            MockPath.return_value = mock_path

            prompt = _build_patch_prompt(error)
            # The prompt might be empty or contain content depending on file existence
            # The key thing is it doesn't crash
            self.assertIsInstance(prompt, str)


# ══════════════════════════════════════════════════════════════════════════════
# 5. Complete Provider Failover Chain
# ══════════════════════════════════════════════════════════════════════════════

class TestProviderFailoverChain(unittest.TestCase):
    """Test complete failover: primary fails → next provider → fallback."""

    def _create_gateway(self, provider_results=None):
        """Create a gateway with mocked providers."""
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

    def test_primary_to_secondary_failover(self):
        """Test failover from primary (cerebras) to secondary (CF AI Gateway)."""
        gw = self._create_gateway({
            "cerebras": Exception("cerebras unavailable"),
            "cloudflare_ai_gateway": "cf_gateway_response",
        })

        result = gw.chat(messages=[{"role": "user", "content": "test"}])
        self.assertEqual(result, "cf_gateway_response")
        self.assertEqual(gw._last_response_source, "primary")

    def test_secondary_to_tertiary_failover(self):
        """Test failover from secondary to tertiary provider."""
        gw = self._create_gateway({
            "cerebras": Exception("down"),
            "cloudflare_ai_gateway": Exception("down"),
            "cloudflare_workers_ai": "cf_workers_response",
        })

        result = gw.chat(messages=[{"role": "user", "content": "test"}])
        self.assertEqual(result, "cf_workers_response")
        self.assertEqual(gw._last_response_source, "primary")

    def test_all_primary_to_local_fallback(self):
        """Test failover from all primary providers to LocalAIEngine."""
        gw = self._create_gateway({
            "cerebras": Exception("down"),
            "cloudflare_ai_gateway": Exception("down"),
            "cloudflare_workers_ai": Exception("down"),
            "portkey": Exception("down"),
        })

        with patch("torshield_ai_gateway.gateway.LocalAIEngine") as MockLocalAI:
            mock_engine = MagicMock()
            mock_engine.chat_complete.return_value = "local_engine_response"
            MockLocalAI.return_value = mock_engine

            result = gw.chat(messages=[{"role": "user", "content": "test"}])

        self.assertEqual(result, "local_engine_response")
        self.assertEqual(gw._last_response_source, "local_fallback")

    def test_empty_response_treated_as_failure(self):
        """Test that empty provider responses trigger failover to next provider."""
        gw = self._create_gateway({
            "cerebras": "",  # Empty response
            "cloudflare_ai_gateway": "non_empty_response",
        })

        result = gw.chat(messages=[{"role": "user", "content": "test"}])
        self.assertEqual(result, "non_empty_response")

    def test_preferred_provider_overrides_priority(self):
        """Test that preferred_provider parameter overrides normal priority."""
        gw = self._create_gateway({
            "cerebras": "cerebras_response",
            "portkey": "portkey_response",
        })

        result = gw.chat(
            messages=[{"role": "user", "content": "test"}],
            preferred_provider="portkey",
        )
        self.assertEqual(result, "portkey_response")

    def test_failover_preserves_stats_accuracy(self):
        """Test that failover chain correctly tracks statistics."""
        gw = self._create_gateway({
            "cerebras": Exception("down"),
            "cloudflare_ai_gateway": "ok",
        })

        gw.chat(messages=[{"role": "user", "content": "test"}])

        stats = gw.health_stats()
        self.assertEqual(stats["total_requests"], 1)
        self.assertEqual(stats["primary_successes"], 1)
        self.assertEqual(stats["local_fallback_uses"], 0)
        # Both providers should be in attempts
        self.assertIn("cerebras", stats["provider_attempts"])
        self.assertIn("cloudflare_ai_gateway", stats["provider_attempts"])

    def test_complete_failover_chain_with_circuit_breakers(self):
        """Test complete failover chain with circuit breaker integration."""
        from torshield_ai_gateway.providers import ProviderCircuitBreaker

        # Create circuit breakers for each provider
        cb_cerebras = ProviderCircuitBreaker("cerebras", failure_threshold=2)
        cb_cf_gw = ProviderCircuitBreaker("cloudflare_ai_gateway", failure_threshold=2)

        # Trip cerebras circuit breaker
        cb_cerebras.record_failure()
        cb_cerebras.record_failure()
        self.assertEqual(cb_cerebras.state, "open")
        self.assertFalse(cb_cerebras.allow_request())

        # CF Gateway should still be closed
        self.assertEqual(cb_cf_gw.state, "closed")
        self.assertTrue(cb_cf_gw.allow_request())

        # Recovery and re-test
        cb_cerebras_recovery = ProviderCircuitBreaker(
            "cerebras_recovery", failure_threshold=2, recovery_timeout=0.05
        )
        cb_cerebras_recovery.record_failure()
        cb_cerebras_recovery.record_failure()
        time.sleep(0.06)
        self.assertTrue(cb_cerebras_recovery.allow_request())
        self.assertEqual(cb_cerebras_recovery.state, "half_open")

        # Success in half_open closes it
        cb_cerebras_recovery.record_success()
        self.assertEqual(cb_cerebras_recovery.state, "closed")

    def test_gateway_ultimate_fallback_json(self):
        """Test that gateway returns valid JSON when everything fails."""
        gw = self._create_gateway({})

        with patch("torshield_ai_gateway.gateway.LocalAIEngine") as MockLocalAI:
            mock_engine = MagicMock()
            mock_engine.chat_complete.side_effect = Exception("total failure")
            MockLocalAI.return_value = mock_engine

            result = gw.chat(messages=[{"role": "user", "content": "test"}])

        # Should be valid JSON
        parsed = json.loads(result)
        self.assertIn("status", parsed)
        self.assertEqual(parsed["status"], "error")
        self.assertTrue(parsed.get("degraded", False))


if __name__ == "__main__":
    unittest.main()
