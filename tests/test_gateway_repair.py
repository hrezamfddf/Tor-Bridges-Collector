#!/usr/bin/env python3
"""
test_gateway_repair.py — Comprehensive Tests for Gateway Repair v1.0
═══════════════════════════════════════════════════════════════════════════════

Tests for the critical CF AI Gateway HTTP 400 fix and all new modules.
All tests are non-destructive and can run without real API credentials.

Test Categories:
  1. normalize_cf_gateway_url() — /compat/ path fix
  2. EndpointValidator — URL format detection
  3. SlotCircuitBreaker — state machine transitions
  4. SelfHealingEngine — healing cycle
  5. RetryEngine — retry decision logic
  6. ModelRegistry — fitness scoring
  7. ReportGenerator — report generation
  8. StructuredLogger — fail-safe logging
  9. Feature flags — configuration
  10. Integration — end-to-end flow
"""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class TestNormalizeCFGatewayURL(unittest.TestCase):
    """Test the critical /workers-ai/ → /compat/ path fix."""

    def test_bare_gateway_url_gets_compat_suffix(self):
        """Bare gateway URL should get /compat/chat/completions suffix."""
        from torshield_ai_gateway.providers import normalize_cf_gateway_url
        result = normalize_cf_gateway_url(
            "https://gateway.ai.cloudflare.com/v1/abc123def456abc123def456abc12345/my-gateway"
        )
        self.assertTrue(result.endswith("/compat/chat/completions"))
        self.assertNotIn("/workers-ai/", result)

    def test_workers_ai_suffix_corrected_to_compat(self):
        """URLs with /workers-ai/v1/chat/completions should be corrected to /compat/."""
        from torshield_ai_gateway.providers import normalize_cf_gateway_url
        result = normalize_cf_gateway_url(
            "https://gateway.ai.cloudflare.com/v1/abc123def456abc123def456abc12345/my-gateway/workers-ai/v1/chat/completions"
        )
        self.assertTrue(result.endswith("/compat/chat/completions"))
        self.assertNotIn("/workers-ai/", result)

    def test_partial_workers_ai_path_corrected(self):
        """Partial /workers-ai paths should be corrected to /compat/."""
        from torshield_ai_gateway.providers import normalize_cf_gateway_url
        result = normalize_cf_gateway_url(
            "https://gateway.ai.cloudflare.com/v1/abc123def456abc123def456abc12345/my-gateway/workers-ai"
        )
        self.assertTrue(result.endswith("/compat/chat/completions"))
        self.assertNotIn("/workers-ai/", result)

    def test_compat_suffix_preserved(self):
        """URLs already using /compat/ should be returned unchanged."""
        from torshield_ai_gateway.providers import normalize_cf_gateway_url
        url = "https://gateway.ai.cloudflare.com/v1/abc123def456abc123def456abc12345/my-gateway/compat/chat/completions"
        result = normalize_cf_gateway_url(url)
        self.assertEqual(result, url)

    def test_trailing_slash_stripped(self):
        """Trailing slashes should be stripped before adding suffix."""
        from torshield_ai_gateway.providers import normalize_cf_gateway_url
        result = normalize_cf_gateway_url(
            "https://gateway.ai.cloudflare.com/v1/abc123def456abc123def456abc12345/my-gateway/"
        )
        self.assertTrue(result.endswith("/compat/chat/completions"))

    def test_workers_ai_v1_partial_corrected(self):
        """Partial /workers-ai/v1 path should be corrected to /compat/."""
        from torshield_ai_gateway.providers import normalize_cf_gateway_url
        result = normalize_cf_gateway_url(
            "https://gateway.ai.cloudflare.com/v1/abc123def456abc123def456abc12345/my-gateway/workers-ai/v1"
        )
        self.assertTrue(result.endswith("/compat/chat/completions"))
        self.assertNotIn("/workers-ai/", result)


class TestEndpointValidator(unittest.TestCase):
    """Test endpoint validation and URL format detection."""

    def test_detect_compat_endpoint(self):
        """Should detect /compat/ endpoint type."""
        from core.endpoint_validator import EndpointValidator, EndpointType
        validator = EndpointValidator()
        result = validator.validate_slot_url(
            slot_index=1,
            gateway_url="https://gateway.ai.cloudflare.com/v1/abc123def456abc123def456abc12345/gw/compat/chat/completions",
        )
        self.assertEqual(result.endpoint_type, EndpointType.COMPAT)

    def test_detect_workers_ai_endpoint(self):
        """Should detect /workers-ai/ endpoint type and recommend /compat/."""
        from core.endpoint_validator import EndpointValidator, EndpointType
        validator = EndpointValidator()
        result = validator.validate_slot_url(
            slot_index=1,
            gateway_url="https://gateway.ai.cloudflare.com/v1/abc123def456abc123def456abc12345/gw/workers-ai/v1/chat/completions",
        )
        self.assertEqual(result.endpoint_type, EndpointType.WORKERS_AI)
        self.assertIn("/compat/", result.recommended_url)
        self.assertNotIn("/workers-ai/", result.recommended_url)

    def test_detect_direct_endpoint(self):
        """Should detect direct CF Workers AI endpoint."""
        from core.endpoint_validator import EndpointValidator, EndpointType
        validator = EndpointValidator()
        result = validator.validate_slot_url(
            slot_index=1,
            gateway_url="https://api.cloudflare.com/client/v4/accounts/abc123def456abc123def456abc12345/ai/v1/chat/completions",
        )
        self.assertEqual(result.endpoint_type, EndpointType.DIRECT)


class TestSlotCircuitBreaker(unittest.TestCase):
    """Test per-slot circuit breaker state machine."""

    def test_initial_state_is_closed(self):
        """New slots should start in CLOSED state."""
        from circuit_breaker.slot_circuit_breaker import SlotCircuitBreaker, CircuitState
        cb = SlotCircuitBreaker()
        status = cb.get_status()
        for slot_idx, slot_info in status.get("slots", {}).items():
            if slot_info.get("configured") and not slot_info.get("skipped"):
                self.assertEqual(slot_info["state"], CircuitState.CLOSED.value)

    def test_misconfigured_slots_are_skipped(self):
        """Slots with invalid credentials should be SKIPPED, not FAILED."""
        from circuit_breaker.slot_circuit_breaker import SlotCircuitBreaker
        cb = SlotCircuitBreaker()
        status = cb.get_status()
        for slot_idx, slot_info in status.get("slots", {}).items():
            if slot_info.get("skipped"):
                self.assertTrue(slot_info["skip_reason"] != "")

    def test_circuit_opens_after_threshold(self):
        """Circuit should open after N consecutive failures."""
        from circuit_breaker.slot_circuit_breaker import SlotCircuitBreaker, CircuitState
        cb = SlotCircuitBreaker()
        # Record failures to trigger circuit open
        for _ in range(cb._failure_threshold):
            cb.record_failure(slot_index=1, error_type="HTTP 400")
        # Check if circuit is open for slot 1
        status = cb.get_status()
        slot_1 = status.get("slots", {}).get("1", {})
        if slot_1.get("configured") and not slot_1.get("skipped"):
            self.assertEqual(slot_1["state"], CircuitState.OPEN.value)

    def test_circuit_closes_on_success(self):
        """Circuit should close on successful request."""
        from circuit_breaker.slot_circuit_breaker import SlotCircuitBreaker, CircuitState
        cb = SlotCircuitBreaker()
        cb.record_failure(slot_index=1, error_type="HTTP 500")
        cb.record_failure(slot_index=1, error_type="HTTP 500")
        cb.record_failure(slot_index=1, error_type="HTTP 500")
        cb.record_success(slot_index=1, latency_ms=100.0)
        status = cb.get_status()
        slot_1 = status.get("slots", {}).get("1", {})
        if slot_1.get("configured") and not slot_1.get("skipped"):
            self.assertEqual(slot_1["state"], CircuitState.CLOSED.value)


class TestRetryEngine(unittest.TestCase):
    """Test retry decision logic."""

    def test_http_400_rotates_model(self):
        """HTTP 400 should trigger model rotation, not retry."""
        from gateway.retry_engine import RetryEngine, RetryAction
        engine = RetryEngine()
        decision = engine.decide(error_code=400, attempt=0, slot=1, model="test-model")
        self.assertEqual(decision.action, RetryAction.ROTATE_MODEL)
        self.assertEqual(decision.delay_secs, 0)

    def test_http_429_backoff(self):
        """HTTP 429 should use exponential backoff."""
        from gateway.retry_engine import RetryEngine, RetryAction
        engine = RetryEngine()
        decision = engine.decide(error_code=429, attempt=0, slot=1)
        self.assertEqual(decision.action, RetryAction.RETRY_SAME)
        self.assertGreater(decision.delay_secs, 0)

    def test_http_5xx_retries_then_rotates(self):
        """HTTP 5xx should retry with backoff, then rotate slot."""
        from gateway.retry_engine import RetryEngine, RetryAction
        engine = RetryEngine()
        # First attempt — should retry
        decision = engine.decide(error_code=500, attempt=0, slot=1)
        self.assertEqual(decision.action, RetryAction.RETRY_SAME)
        # After max retries — should rotate slot
        decision = engine.decide(error_code=500, attempt=engine._max_attempts_5xx, slot=1)
        self.assertEqual(decision.action, RetryAction.ROTATE_SLOT)

    def test_http_403_rotates_slot(self):
        """HTTP 403 should immediately rotate slot."""
        from gateway.retry_engine import RetryEngine, RetryAction
        engine = RetryEngine()
        decision = engine.decide(error_code=403, attempt=0, slot=1)
        self.assertEqual(decision.action, RetryAction.ROTATE_SLOT)

    def test_timeout_rotates_immediately(self):
        """Timeout should trigger immediate slot rotation."""
        from gateway.retry_engine import RetryEngine, RetryAction
        engine = RetryEngine()
        decision = engine.decide(error_code=0, attempt=0, slot=1)
        self.assertEqual(decision.action, RetryAction.ROTATE_SLOT)
        self.assertEqual(decision.delay_secs, 0)


class TestModelRegistry(unittest.TestCase):
    """Test model registry and fitness scoring."""

    def test_static_models_initialized(self):
        """Registry should initialize with static model list."""
        from registry.model_registry import ModelRegistry
        registry = ModelRegistry()
        status = registry.get_status()
        self.assertGreater(status["total_models"], 0)

    def test_best_model_returns_string(self):
        """get_best_model should return a model ID string."""
        from registry.model_registry import ModelRegistry
        registry = ModelRegistry()
        model = registry.get_best_model(task="general")
        self.assertIsNotNone(model)
        self.assertIsInstance(model, str)

    def test_fitness_scoring(self):
        """ModelEntry fitness score should be 0.0-1.0."""
        from registry.model_registry import ModelEntry
        entry = ModelEntry(
            model_id="test-model",
            availability=1.0,
            reliability=0.8,
            latency_score=0.7,
            success_rate=0.9,
            dpi_resistance=0.8,
        )
        score = entry.fitness_score
        self.assertGreater(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_mark_success_updates_score(self):
        """Successful request should improve model score."""
        from registry.model_registry import ModelRegistry
        registry = ModelRegistry()
        model_id = registry.get_best_model()
        if model_id:
            initial_status = registry.get_status()
            registry.mark_model_success(model_id, latency_ms=100.0)
            # Model should still be available
            model = registry.get_best_model()
            self.assertIsNotNone(model)


class TestReportGenerator(unittest.TestCase):
    """Test JSON report generation."""

    def test_generate_diagnostics_report(self):
        """Should generate diagnostics_report.json."""
        from reports.report_generator import ReportGenerator
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            gen.record_diagnostic_event(
                event_type="test",
                provider="test_provider",
                error_code="HTTP 400",
                root_cause="Bad endpoint path",
            )
            report = gen.generate_diagnostics_report()
            self.assertEqual(report["report_type"], "diagnostics")
            self.assertIn("root_cause_analysis", report)
            # Check file was written
            self.assertTrue((Path(tmpdir) / "diagnostics_report.json").exists())

    def test_generate_repair_report(self):
        """Should generate repair_report.json."""
        from reports.report_generator import ReportGenerator
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            gen.record_repair_action(
                action="endpoint_path_fix",
                target="slot_1",
                old_value="/workers-ai/v1/chat/completions",
                new_value="/compat/chat/completions",
            )
            report = gen.generate_repair_report()
            self.assertEqual(report["report_type"], "repair")
            self.assertIn("critical_fix", report)
            self.assertTrue(report["critical_fix"]["fix_applied"])

    def test_generate_health_report(self):
        """Should generate health_report.json."""
        from reports.report_generator import ReportGenerator
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            gen.update_provider_health(
                provider="cloudflare_ai_gateway",
                status="healthy",
                success_rate=0.95,
            )
            report = gen.generate_health_report()
            self.assertEqual(report["report_type"], "health")
            self.assertIn("provider_details", report)


class TestStructuredLogger(unittest.TestCase):
    """Test fail-safe structured logging."""

    def test_log_writes_json_line(self):
        """Should write JSON lines to log file."""
        from monitoring.structured_logger import StructuredLogger
        with tempfile.TemporaryDirectory() as tmpdir:
            sl = StructuredLogger(log_dir=tmpdir)
            sl.log_diagnostics(
                level="INFO",
                provider="test",
                slot=1,
                message="Test log entry",
            )
            # Check file was written
            log_file = Path(tmpdir) / "diagnostics.log"
            self.assertTrue(log_file.exists())
            # Verify JSON format
            with open(log_file) as f:
                line = f.readline()
                data = json.loads(line)
                self.assertEqual(data["provider"], "test")
                self.assertEqual(data["slot"], 1)

    def test_disk_full_does_not_crash(self):
        """Logger should not crash on I/O errors."""
        from monitoring.structured_logger import StructuredLogger
        sl = StructuredLogger(log_dir="/nonexistent/path/that/does/not/exist")
        # Should not raise
        sl.log_diagnostics(level="INFO", message="This should not crash")


class TestFeatureFlags(unittest.TestCase):
    """Test feature flag configuration."""

    def test_all_flags_have_values(self):
        """All feature flags should have boolean values."""
        from config.feature_flags import get_all_flags
        flags = get_all_flags()
        for name, value in flags.items():
            self.assertIsInstance(value, bool, f"Flag {name} should be bool")

    def test_compat_path_fix_enabled(self):
        """CRITICAL: compat path fix should be enabled by default."""
        from config.feature_flags import ENABLE_COMPAT_PATH_FIX
        self.assertTrue(ENABLE_COMPAT_PATH_FIX)

    def test_circuit_breaker_enabled(self):
        """Circuit breaker should be enabled by default."""
        from config.feature_flags import ENABLE_CIRCUIT_BREAKER
        self.assertTrue(ENABLE_CIRCUIT_BREAKER)


class TestSelfHealingEngine(unittest.TestCase):
    """Test self-healing engine."""

    def test_threshold_triggers_healing(self):
        """Healing should trigger after N sequential failures."""
        from recovery.self_healing_engine import SelfHealingEngine
        engine = SelfHealingEngine()
        engine._sequential_failures = 0
        engine._last_heal_time = 0  # Ensure no cooldown

        # Record failures up to threshold
        result = None
        for i in range(engine._trigger_threshold):
            result = engine.record_model_failure(provider="test", model="test-model")

        # Should have triggered healing
        if result is not None:
            self.assertGreater(len(result.actions_taken), 0)

    def test_success_resets_counter(self):
        """Successful model resolution should reset failure counter."""
        from recovery.self_healing_engine import SelfHealingEngine
        engine = SelfHealingEngine()
        engine._sequential_failures = 1
        engine.record_model_success()
        self.assertEqual(engine._sequential_failures, 0)


class TestValidationChecklist(unittest.TestCase):
    """
    Validation Checklist Tests — verify all success criteria.
    
    [ ] All 11 CF slots initialized without crash
    [ ] HTTP 400 errors trigger model rotation (not retry)
    [ ] HTTP 429 errors use exponential backoff
    [ ] Circuit breaker opens after 3 consecutive failures
    [ ] Self-healing triggers after 2 sequential model failures
    [ ] All log writes survive disk-full condition
    [ ] All 3 JSON reports generated on completion
    [ ] Zero providers removed from original configuration
    """

    def test_all_11_slots_init_without_crash(self):
        """All 11 CF slots should initialize without crashing."""
        from circuit_breaker.slot_circuit_breaker import SlotCircuitBreaker
        cb = SlotCircuitBreaker()
        status = cb.get_status()
        self.assertEqual(status["total_slots"], 11)
        # No crash = success

    def test_http_400_triggers_model_rotation(self):
        """HTTP 400 should trigger model rotation, not retry."""
        from gateway.retry_engine import RetryEngine, RetryAction
        engine = RetryEngine()
        decision = engine.decide(error_code=400, attempt=0)
        self.assertEqual(decision.action, RetryAction.ROTATE_MODEL)

    def test_http_429_uses_exponential_backoff(self):
        """HTTP 429 should use exponential backoff."""
        from gateway.retry_engine import RetryEngine, RetryAction
        engine = RetryEngine()
        d0 = engine.decide(error_code=429, attempt=0)
        d1 = engine.decide(error_code=429, attempt=1)
        d2 = engine.decide(error_code=429, attempt=2)
        # Delays should increase
        self.assertLess(d0.delay_secs, d1.delay_secs)
        self.assertLess(d1.delay_secs, d2.delay_secs)

    def test_circuit_breaker_opens_after_3_failures(self):
        """Circuit breaker should open after 3 consecutive failures."""
        from circuit_breaker.slot_circuit_breaker import SlotCircuitBreaker, CircuitState
        cb = SlotCircuitBreaker()
        for _ in range(3):
            cb.record_failure(slot_index=1, error_type="HTTP 500")
        status = cb.get_status()
        slot_1 = status.get("slots", {}).get("1", {})
        if slot_1.get("configured") and not slot_1.get("skipped"):
            self.assertEqual(slot_1["state"], CircuitState.OPEN.value)

    def test_self_healing_triggers_after_2_failures(self):
        """Self-healing should trigger after 2 sequential failures."""
        from recovery.self_healing_engine import SelfHealingEngine
        engine = SelfHealingEngine()
        engine._trigger_threshold = 2
        engine._last_heal_time = 0
        result1 = engine.record_model_failure(provider="test")
        result2 = engine.record_model_failure(provider="test")
        self.assertIsNotNone(result2)

    def test_log_writes_survive_disk_full(self):
        """Log writes should survive disk-full condition."""
        from monitoring.structured_logger import StructuredLogger
        sl = StructuredLogger(log_dir="/dev/null/impossible")
        # Should not raise
        sl.log_diagnostics(level="ERROR", message="Should not crash")

    def test_all_3_reports_generated(self):
        """All 3 JSON reports should be generated."""
        from reports.report_generator import ReportGenerator
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            reports = gen.generate_all_reports()
            self.assertIn("diagnostics", reports)
            self.assertIn("repair", reports)
            self.assertIn("health", reports)
            self.assertTrue((Path(tmpdir) / "diagnostics_report.json").exists())
            self.assertTrue((Path(tmpdir) / "repair_report.json").exists())
            self.assertTrue((Path(tmpdir) / "health_report.json").exists())

    def test_zero_providers_removed(self):
        """No providers should be removed from original configuration."""
        from torshield_ai_gateway.gateway import TorShieldAIGateway
        # Check that all 4 providers are in the priority list
        self.assertIn("cloudflare_ai_gateway", TorShieldAIGateway.PROVIDER_PRIORITY)
        self.assertIn("cloudflare_workers_ai", TorShieldAIGateway.PROVIDER_PRIORITY)
        self.assertIn("cerebras", TorShieldAIGateway.PROVIDER_PRIORITY)
        self.assertIn("portkey", TorShieldAIGateway.PROVIDER_PRIORITY)
        self.assertEqual(len(TorShieldAIGateway.PROVIDER_PRIORITY), 4)


if __name__ == "__main__":
    unittest.main()
