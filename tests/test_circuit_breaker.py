"""
tests/test_circuit_breaker.py — Focused circuit breaker tests

Tests:
  - Closed → Open transition
  - Open → Half-Open recovery
  - Failure threshold
  - Recovery timeout
  - Success/failure recording

All tests use unittest.mock to avoid making real API calls.
"""

import os
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestProviderCircuitBreaker(unittest.TestCase):
    """Focused tests on the ProviderCircuitBreaker state machine."""

    def _get_cb(self, provider_name="test", failure_threshold=3, recovery_timeout=0.05):
        """Create a circuit breaker with fast recovery for testing."""
        from torshield_ai_gateway.providers import ProviderCircuitBreaker
        return ProviderCircuitBreaker(
            provider_name=provider_name,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
        )

    # ── Closed State Tests ──────────────────────────────────────────────────

    def test_initial_state_closed(self):
        """Circuit breaker starts in closed state."""
        cb = self._get_cb()
        self.assertEqual(cb.state, "closed")
        self.assertTrue(cb.allow_request())

    def test_closed_allows_all_requests(self):
        """In closed state, all requests should be allowed."""
        cb = self._get_cb()
        for _ in range(20):
            self.assertTrue(cb.allow_request())

    def test_closed_tracks_failure_count(self):
        """In closed state, failures are counted but circuit stays closed."""
        cb = self._get_cb(failure_threshold=5)
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.failure_count, 3)
        self.assertEqual(cb.state, "closed")

    # ── Closed → Open Transition ────────────────────────────────────────────

    def test_transition_closed_to_open(self):
        """Test transition from closed to open when threshold is reached."""
        cb = self._get_cb(failure_threshold=3)
        cb.record_failure()
        self.assertEqual(cb.state, "closed")
        cb.record_failure()
        self.assertEqual(cb.state, "closed")
        cb.record_failure()
        self.assertEqual(cb.state, "open")

    def test_exact_threshold_triggers_open(self):
        """Test that exactly reaching the threshold triggers open."""
        cb = self._get_cb(failure_threshold=5)
        for i in range(4):
            cb.record_failure()
            self.assertEqual(cb.state, "closed", f"Should be closed after {i+1} failures")
        cb.record_failure()  # 5th failure
        self.assertEqual(cb.state, "open")

    def test_beyond_threshold_stays_open(self):
        """Test that failures beyond threshold keep circuit open."""
        cb = self._get_cb(failure_threshold=2)
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "open")
        cb.record_failure()
        self.assertEqual(cb.state, "open")
        self.assertEqual(cb.failure_count, 3)

    # ── Open State Tests ────────────────────────────────────────────────────

    def test_open_rejects_requests(self):
        """In open state, requests should be rejected."""
        cb = self._get_cb(failure_threshold=2)
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "open")
        self.assertFalse(cb.allow_request())

    def test_open_rejects_until_recovery_timeout(self):
        """Circuit stays open until recovery timeout elapses."""
        cb = self._get_cb(failure_threshold=2, recovery_timeout=2.0)
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "open")
        # Should still reject immediately after opening
        self.assertFalse(cb.allow_request())

    # ── Open → Half-Open Transition ─────────────────────────────────────────

    def test_transition_open_to_half_open(self):
        """Test transition from open to half_open after recovery timeout."""
        cb = self._get_cb(failure_threshold=2, recovery_timeout=0.05)
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "open")

        # Wait for recovery timeout
        time.sleep(0.06)

        self.assertTrue(cb.allow_request())
        self.assertEqual(cb.state, "half_open")

    def test_half_open_allows_one_request(self):
        """In half_open state, one request is allowed through."""
        cb = self._get_cb(failure_threshold=2, recovery_timeout=0.05)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.06)

        # First call transitions to half_open and allows
        self.assertTrue(cb.allow_request())
        # In half_open, subsequent calls are also allowed
        self.assertTrue(cb.allow_request())

    # ── Half-Open → Closed (Success) ───────────────────────────────────────

    def test_half_open_to_closed_on_success(self):
        """Test transition from half_open to closed on successful request."""
        cb = self._get_cb(failure_threshold=2, recovery_timeout=0.05)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.06)
        cb.allow_request()  # triggers half_open

        cb.record_success()
        self.assertEqual(cb.state, "closed")
        self.assertEqual(cb.failure_count, 0)

    # ── Half-Open → Open (Failure) ─────────────────────────────────────────

    def test_half_open_to_open_on_failure(self):
        """Test transition from half_open back to open on failure."""
        cb = self._get_cb(failure_threshold=2, recovery_timeout=0.05)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.06)
        cb.allow_request()  # triggers half_open

        cb.record_failure()
        self.assertEqual(cb.state, "open")

    # ── Success Recording ───────────────────────────────────────────────────

    def test_success_resets_failure_count(self):
        """Test that recording success resets failure count to zero."""
        cb = self._get_cb(failure_threshold=5)
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.failure_count, 3)

        cb.record_success()
        self.assertEqual(cb.failure_count, 0)
        self.assertEqual(cb.state, "closed")

    def test_success_from_open_closes_circuit(self):
        """Test that success from any state closes the circuit."""
        cb = self._get_cb(failure_threshold=2, recovery_timeout=0.05)
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "open")

        # Manually set to half_open and then record success
        time.sleep(0.06)
        cb.allow_request()
        cb.record_success()
        self.assertEqual(cb.state, "closed")

    # ── Failure Recording ───────────────────────────────────────────────────

    def test_failure_updates_timestamp(self):
        """Test that recording failure updates last_failure_time."""
        cb = self._get_cb()
        before = time.time()
        cb.record_failure()
        after = time.time()
        self.assertGreaterEqual(cb.last_failure_time, before - 0.1)
        self.assertLessEqual(cb.last_failure_time, after + 0.1)

    # ── Recovery Timeout ────────────────────────────────────────────────────

    def test_recovery_timeout_respected(self):
        """Test that circuit stays open until recovery timeout."""
        cb = self._get_cb(failure_threshold=2, recovery_timeout=0.5)
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "open")

        # Should still be open after a short wait
        time.sleep(0.1)
        self.assertFalse(cb.allow_request())
        self.assertEqual(cb.state, "open")

    def test_custom_recovery_timeout(self):
        """Test that custom recovery timeout is used."""
        from torshield_ai_gateway.providers import ProviderCircuitBreaker
        cb = ProviderCircuitBreaker(
            provider_name="test",
            failure_threshold=2,
            recovery_timeout=600.0,  # 10 minutes
        )
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "open")
        self.assertEqual(cb.recovery_timeout, 600.0)

    # ── Integration-style Tests ─────────────────────────────────────────────

    def test_full_lifecycle(self):
        """Test complete circuit breaker lifecycle:
        closed → open → half_open → closed
        """
        cb = self._get_cb(failure_threshold=2, recovery_timeout=0.05)

        # Phase 1: Closed state - allow requests
        self.assertTrue(cb.allow_request())
        self.assertEqual(cb.state, "closed")

        # Phase 2: Trigger failures to open circuit
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "open")
        self.assertFalse(cb.allow_request())

        # Phase 3: Wait for recovery
        time.sleep(0.06)
        self.assertTrue(cb.allow_request())
        self.assertEqual(cb.state, "half_open")

        # Phase 4: Successful request closes circuit
        cb.record_success()
        self.assertEqual(cb.state, "closed")
        self.assertTrue(cb.allow_request())

    def test_flapping_circuit(self):
        """Test circuit that oscillates between open and half_open."""
        cb = self._get_cb(failure_threshold=2, recovery_timeout=0.05)

        # First open
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "open")

        # Recovery → half_open → failure → open again
        time.sleep(0.06)
        cb.allow_request()
        cb.record_failure()
        self.assertEqual(cb.state, "open")

        # Second recovery → half_open → failure → open again
        time.sleep(0.06)
        cb.allow_request()
        cb.record_failure()
        self.assertEqual(cb.state, "open")

        # Third recovery → half_open → success → closed
        time.sleep(0.06)
        cb.allow_request()
        cb.record_success()
        self.assertEqual(cb.state, "closed")

    def test_multiple_circuit_breakers_independent(self):
        """Test that multiple circuit breakers operate independently."""
        cb1 = self._get_cb(provider_name="provider1", failure_threshold=2, recovery_timeout=0.05)
        cb2 = self._get_cb(provider_name="provider2", failure_threshold=4, recovery_timeout=0.05)

        # Open cb1 but not cb2
        cb1.record_failure()
        cb1.record_failure()
        self.assertEqual(cb1.state, "open")
        self.assertEqual(cb2.state, "closed")

        # cb2 still allows requests
        self.assertTrue(cb2.allow_request())

        # Open cb2 with more failures
        cb2.record_failure()
        cb2.record_failure()
        cb2.record_failure()
        cb2.record_failure()
        self.assertEqual(cb2.state, "open")


if __name__ == "__main__":
    unittest.main()
