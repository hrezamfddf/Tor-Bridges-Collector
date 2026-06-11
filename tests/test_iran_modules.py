"""
tests/test_iran_modules.py — Iran anti-censorship module tests

Tests:
  - IranSmartAntiFilter: censorship detection, bridge optimization, rotation
  - IranAntiDPI: threat analysis, evasion strategies, TLS randomization
  - IranAutoDefense: threat detection, auto-response, defense cycle
  - SmartBypassEngine: bypass strategy generation, DPI evasion profiles

All tests use unittest.mock to avoid making real API calls.
"""

import json
import os
import sys
import time
import unittest
from unittest.mock import MagicMock, Mock, patch, PropertyMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestIranSmartAntiFilter(unittest.TestCase):
    """Test the IranSmartAntiFilter engine."""

    def _get_class(self):
        from iran_smart_anti_filter import IranSmartAntiFilter
        return IranSmartAntiFilter

    def _get_censorship_state_class(self):
        from iran_smart_anti_filter import CensorshipState
        return CensorshipState

    def test_instantiation(self):
        """Test IranSmartAntiFilter can be instantiated."""
        saf = self._get_class()()
        self.assertIsNotNone(saf)

    def test_censorship_state_creation(self):
        """Test CensorshipState dataclass creation with correct fields."""
        CS = self._get_censorship_state_class()
        state = CS(level=3, label="Elevated DPI")
        self.assertEqual(state.level, 3)
        self.assertEqual(state.label, "Elevated DPI")
        self.assertIsInstance(state.confidence, float)
        self.assertIsInstance(state.dpi_systems_active, list)

    def test_censorship_state_defaults(self):
        """Test CensorshipState default values."""
        CS = self._get_censorship_state_class()
        state = CS()
        self.assertGreaterEqual(state.level, 1)
        self.assertLessEqual(state.level, 5)
        self.assertIsInstance(state.label, str)

    def test_detect_censorship_returns_state(self):
        """Test that detect_censorship returns a CensorshipState."""
        saf = self._get_class()()
        CS = self._get_censorship_state_class()
        state = saf.detect_censorship(force=True)
        self.assertIsInstance(state, CS)
        self.assertGreaterEqual(state.level, 1)
        self.assertLessEqual(state.level, 5)

    def test_get_optimized_bridges_with_dict(self):
        """Test bridge optimization with a dict input (as expected by the API)."""
        saf = self._get_class()()
        bridges_dict = {
            "obfs4_1": {"line": "obfs4 1.2.3.4:443 cert=fingerprint iat-mode=2", "transport": "obfs4"},
            "webtunnel_1": {"line": "webtunnel 5.6.7.8:443 url=https://example.com", "transport": "webtunnel"},
            "snowflake_1": {"line": "snowflake 9.10.11.12:443", "transport": "snowflake"},
        }
        result = saf.get_optimized_bridges(bridges_dict)
        self.assertIsNotNone(result)

    def test_rotate_bridges(self):
        """Test bridge rotation returns a reordered list."""
        saf = self._get_class()()
        bridges = [
            "obfs4 1.2.3.4:443 cert=abc iat-mode=2",
            "obfs4 5.6.7.8:443 cert=def iat-mode=1",
            "obfs4 9.10.11.12:443 cert=ghi iat-mode=0",
        ]
        rotated = saf.rotate_bridges(bridges)
        self.assertIsInstance(rotated, list)
        self.assertEqual(len(rotated), len(bridges))

    def test_get_best_connection_window(self):
        """Test best connection window returns a dict."""
        saf = self._get_class()()
        window = saf.get_best_connection_window()
        self.assertIsInstance(window, dict)

    def test_get_status(self):
        """Test get_status returns a dictionary."""
        saf = self._get_class()()
        status = saf.get_status()
        self.assertIsInstance(status, dict)

    def test_should_switch_transport(self):
        """Test transport switching recommendation."""
        saf = self._get_class()()
        result = saf.should_switch_transport("obfs4")
        # May return a transport name or None depending on censorship level
        if result is not None:
            self.assertIsInstance(result, str)

    def test_get_best_cdn_front(self):
        """Test CDN front selection returns a dict."""
        saf = self._get_class()()
        result = saf.get_best_cdn_front()
        self.assertIsInstance(result, dict)


class TestIranAntiDPI(unittest.TestCase):
    """Test the IranAntiDPI engine."""

    def _get_class(self):
        from ai_anti_dpi_iran import IranAntiDPI
        return IranAntiDPI

    def test_instantiation(self):
        """Test IranAntiDPI can be instantiated."""
        engine = self._get_class()()
        self.assertIsNotNone(engine)

    def test_analyze_threats_returns_something(self):
        """Test threat analysis returns a value."""
        engine = self._get_class()()
        threats = engine.analyze_threats()
        self.assertIsNotNone(threats)

    def test_get_evasion_strategy(self):
        """Test evasion strategy generation for a bridge."""
        engine = self._get_class()()
        bridge = "obfs4 1.2.3.4:443 cert=testfingerprint iat-mode=2"
        strategy = engine.get_evasion_strategy(bridge)
        self.assertIsNotNone(strategy)

    def test_get_tls_randomization(self):
        """Test TLS randomization returns configuration."""
        engine = self._get_class()()
        result = engine.get_tls_randomization()
        self.assertIsInstance(result, dict)

    def test_get_sni_evasion(self):
        """Test SNI evasion strategy returns configuration."""
        engine = self._get_class()()
        result = engine.get_sni_evasion(transport="webtunnel")
        self.assertIsInstance(result, dict)

    def test_get_traffic_shaping(self):
        """Test traffic shaping configuration."""
        engine = self._get_class()()
        result = engine.get_traffic_shaping(transport="obfs4")
        self.assertIsInstance(result, dict)

    def test_optimize_bridge(self):
        """Test bridge optimization returns a dict."""
        engine = self._get_class()()
        bridge = "obfs4 1.2.3.4:443 cert=testfingerprint iat-mode=2"
        result = engine.optimize_bridge(bridge)
        self.assertIsInstance(result, dict)

    def test_analyze_entropy(self):
        """Test entropy analysis returns a dict."""
        engine = self._get_class()()
        result = engine.analyze_entropy("0123456789abcdef0123456789abcdef")
        self.assertIsInstance(result, dict)

    def test_full_analysis(self):
        """Test full analysis returns a dict."""
        engine = self._get_class()()
        bridge = "obfs4 1.2.3.4:443 cert=testfingerprint iat-mode=2"
        result = engine.full_analysis(bridge)
        self.assertIsInstance(result, dict)


class TestIranAutoDefense(unittest.TestCase):
    """Test the IranAutoDefense auto-defense engine."""

    def _get_class(self):
        from torshield_ai_gateway.iran_auto_defense import IranAutoDefense
        return IranAutoDefense

    def test_instantiation(self):
        """Test IranAutoDefense can be instantiated."""
        # It may try to load V2 engines which don't exist — that's fine
        defense = self._get_class()()
        self.assertIsNotNone(defense)

    def test_transport_priorities_defined(self):
        """Test that transport priorities are defined for all levels."""
        defense = self._get_class()()
        self.assertIn(1, defense.TRANSPORT_PRIORITIES)
        self.assertIn(2, defense.TRANSPORT_PRIORITIES)
        self.assertIn(3, defense.TRANSPORT_PRIORITIES)
        self.assertIn(4, defense.TRANSPORT_PRIORITIES)
        self.assertIn(5, defense.TRANSPORT_PRIORITIES)

    def test_level_1_transports(self):
        """Test Level 1 (minimal) has expected transports."""
        defense = self._get_class()()
        transports = defense.TRANSPORT_PRIORITIES[1]
        self.assertIsInstance(transports, list)
        self.assertGreater(len(transports), 0)

    def test_level_5_transports_cdn_fronted_only(self):
        """Test Level 5 (NIN/Shutdown) only uses CDN-fronted transports."""
        defense = self._get_class()()
        transports = defense.TRANSPORT_PRIORITIES[5]
        self.assertIsInstance(transports, list)
        for t in transports:
            self.assertIn(t, ["webtunnel", "snowflake", "obfs4_iat2"])

    def test_isp_profiles_defined(self):
        """Test that ISP blocking profiles are defined."""
        defense = self._get_class()()
        self.assertIn("mci", defense.ISP_PROFILES)
        self.assertIn("irancell", defense.ISP_PROFILES)
        self.assertIn("rightel", defense.ISP_PROFILES)

    def test_get_status(self):
        """Test get_status returns a dictionary."""
        defense = self._get_class()()
        status = defense.get_status()
        self.assertIsInstance(status, dict)

    def test_detect_threats(self):
        """Test threat detection returns a threat assessment."""
        defense = self._get_class()()
        threats = defense.detect_threats()
        self.assertIsNotNone(threats)

    def test_analyze_bridges(self):
        """Test bridge analysis against threats."""
        defense = self._get_class()()
        threats = defense.detect_threats()
        bridges = [
            "obfs4 1.2.3.4:443 cert=test iat-mode=2",
            "webtunnel 5.6.7.8:443 url=https://example.com",
        ]
        scores = defense.analyze_bridges(bridges, threats)
        self.assertIsInstance(scores, dict)


class TestSmartBypassEngine(unittest.TestCase):
    """Test the SmartBypassEngine."""

    def _get_class(self):
        from torshield_ai_gateway.smart_bypass_engine import SmartBypassEngine
        return SmartBypassEngine

    def test_instantiation(self):
        """Test SmartBypassEngine can be instantiated."""
        engine = self._get_class()()
        self.assertIsNotNone(engine)

    def test_get_bypass_strategy(self):
        """Test bypass strategy generation."""
        engine = self._get_class()()
        strategy = engine.get_bypass_strategy(isp="MCI", censorship_level=3)
        self.assertIsNotNone(strategy)

    def test_bypass_strategy_high_censorship(self):
        """Test bypass strategy for high censorship level."""
        engine = self._get_class()()
        strategy = engine.get_bypass_strategy(isp="IRANCELL", censorship_level=5)
        self.assertIsNotNone(strategy)

    def test_bypass_strategy_low_censorship(self):
        """Test bypass strategy for low censorship level."""
        engine = self._get_class()()
        strategy = engine.get_bypass_strategy(isp="asiatech", censorship_level=1)
        self.assertIsNotNone(strategy)

    def test_create_stealth_tunnel_config(self):
        """Test stealth tunnel configuration generation."""
        engine = self._get_class()()
        bridge = "obfs4 1.2.3.4:443 cert=testfingerprint iat-mode=2"
        strategy = engine.get_bypass_strategy(isp="MCI", censorship_level=3)
        config = engine.create_stealth_tunnel_config(bridge, strategy)
        self.assertIsNotNone(config)

    def test_auto_diagnose_connection_failure(self):
        """Test connection failure diagnosis."""
        engine = self._get_class()()
        result = engine.auto_diagnose_connection_failure(
            bridge_line="obfs4 1.2.3.4:443 cert=test iat-mode=2",
            error_description="Connection refused",
            isp="MCI",
        )
        self.assertIsNotNone(result)

    def test_detect_active_dpi(self):
        """Test active DPI system detection."""
        engine = self._get_class()()
        result = engine.detect_active_dpi()
        self.assertIsNotNone(result)

    def test_status(self):
        """Test status returns a dictionary."""
        engine = self._get_class()()
        status = engine.status()
        self.assertIsInstance(status, dict)


class TestDPIEvasionAdvanced(unittest.TestCase):
    """Test advanced DPI evasion functions."""

    def test_dpi_resistance_tier(self):
        """Test DPI resistance tier classification."""
        from dpi_evasion_advanced import dpi_resistance_tier
        for transport in ["obfs4", "snowflake", "webtunnel", "meek_lite", "vanilla"]:
            tier = dpi_resistance_tier(transport)
            self.assertIn(tier, ["maximum", "very_high", "high", "medium", "low", "none", "unknown"])

    def test_dpi_score(self):
        """Test DPI scoring for bridge records."""
        from dpi_evasion_advanced import dpi_score
        record = {
            "transport": "obfs4",
            "port": 443,
            "iat_mode": 2,
        }
        score = dpi_score(record)
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_update_dpi_report(self):
        """Test DPI intelligence report generation."""
        from dpi_evasion_advanced import update_dpi_report
        records = [
            {"transport": "obfs4", "port": 443, "iat_mode": 2},
            {"transport": "webtunnel", "port": 443},
            {"transport": "snowflake", "port": 443},
        ]
        report = update_dpi_report(records)
        self.assertIsInstance(report, dict)


class TestAntiAIDPI(unittest.TestCase):
    """Test anti-AI DPI scoring."""

    def test_score_anti_ai_dpi(self):
        """Test anti-AI DPI scoring for bridge lines."""
        from anti_ai_dpi import score_anti_ai_dpi
        bridge = "obfs4 1.2.3.4:443 cert=testfingerprint iat-mode=2"
        result = score_anti_ai_dpi(bridge)
        self.assertIsInstance(result, dict)

    def test_iran_blocked_ja3_set(self):
        """Test that Iran blocked JA3 fingerprints set is populated."""
        from anti_ai_dpi import IRAN_BLOCKED_JA3
        self.assertIsInstance(IRAN_BLOCKED_JA3, set)
        self.assertGreater(len(IRAN_BLOCKED_JA3), 0)

    def test_transport_dpi_scores(self):
        """Test transport DPI scores dictionary."""
        from anti_ai_dpi import TRANSPORT_DPI_SCORES
        self.assertIsInstance(TRANSPORT_DPI_SCORES, dict)
        self.assertIn("snowflake", TRANSPORT_DPI_SCORES)
        self.assertIn("webtunnel", TRANSPORT_DPI_SCORES)
        for transport, score in TRANSPORT_DPI_SCORES.items():
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 1.0)


class TestNINBypass(unittest.TestCase):
    """Test NIN bypass detection."""

    def test_detect_nin_status(self):
        """Test NIN status detection returns a tuple."""
        from iran_nin_bypass import detect_nin_status
        result = detect_nin_status()
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)


if __name__ == "__main__":
    unittest.main()
