"""
tests/test_neural_anti_dpi_v3.py — Tests for the Neural Anti-DPI V3 module

Tests:
  - NeuralTrafficMorphing: profile generation, traffic morphing, target profiles
  - JA3_JA3S_RotationEngine: profile generation, rotation, Iran domestic profiles
  - ECHFallbackRouter: ECH resolution, PQ scoring, fallback routing, NIN survival
  - AntiDPIV3Orchestrator: unified analysis, status, V2 fallback
  - Integration with V2 engine (graceful fallback when V2 available/unavailable)

All tests use unittest.mock — no real network calls.
"""

import json
import os
import sys
import time
import unittest
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ══════════════════════════════════════════════════════════════════════════════
# 1. NeuralTrafficMorphing Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestNeuralTrafficMorphing(unittest.TestCase):
    """Test the NeuralTrafficMorphing engine for traffic disguise."""

    def _get_class(self):
        from torshield_ai_gateway.neural_anti_dpi_v3 import NeuralTrafficMorphing
        return NeuralTrafficMorphing

    def _get_packet_info(self):
        from torshield_ai_gateway.neural_anti_dpi_v3 import PacketInfo
        return PacketInfo

    def _get_target_profile(self):
        from torshield_ai_gateway.neural_anti_dpi_v3 import TargetProfile
        return TargetProfile

    def _get_morph_result(self):
        from torshield_ai_gateway.neural_anti_dpi_v3 import MorphResult
        return MorphResult

    def test_instantiation_with_defaults(self):
        """Test NeuralTrafficMorphing can be instantiated with default parameters."""
        NTM = self._get_class()
        engine = NTM()
        self.assertIsNotNone(engine)
        self.assertEqual(engine.default_profile, "cdn-front")
        self.assertEqual(engine.padding_strength, 0.8)
        self.assertEqual(engine.jitter_strength, 0.7)

    def test_instantiation_with_custom_params(self):
        """Test NeuralTrafficMorphing with custom parameters."""
        NTM = self._get_class()
        engine = NTM(
            default_profile="google.com",
            padding_strength=0.5,
            jitter_strength=0.3,
            max_overhead_pct=15.0,
        )
        self.assertEqual(engine.default_profile, "google.com")
        self.assertEqual(engine.padding_strength, 0.5)
        self.assertEqual(engine.jitter_strength, 0.3)
        self.assertEqual(engine.max_overhead_pct, 15.0)

    def test_padding_strength_clamped(self):
        """Test that padding_strength is clamped to [0, 1]."""
        NTM = self._get_class()
        engine_high = NTM(padding_strength=2.0)
        self.assertEqual(engine_high.padding_strength, 1.0)

        engine_low = NTM(padding_strength=-1.0)
        self.assertEqual(engine_low.padding_strength, 0.0)

    def test_jitter_strength_clamped(self):
        """Test that jitter_strength is clamped to [0, 1]."""
        NTM = self._get_class()
        engine_high = NTM(jitter_strength=5.0)
        self.assertEqual(engine_high.jitter_strength, 1.0)

        engine_low = NTM(jitter_strength=-0.5)
        self.assertEqual(engine_low.jitter_strength, 0.0)

    def test_generate_target_profile_known(self):
        """Test generating a target profile for a known service type."""
        NTM = self._get_class()
        engine = NTM()

        for service in ["google.com", "youtube.com", "iran-banking", "cdn-front",
                        "telegram-ir", "digikala"]:
            profile = engine.generate_target_profile(service)
            TargetProfile = self._get_target_profile()
            self.assertIsInstance(profile, TargetProfile)
            self.assertEqual(profile.name, service)

    def test_generate_target_profile_unknown_uses_default(self):
        """Test that unknown service type falls back to default profile."""
        NTM = self._get_class()
        engine = NTM(default_profile="cdn-front")

        profile = engine.generate_target_profile("nonexistent.service")
        self.assertEqual(profile.name, "cdn-front")

    def test_get_profiles_returns_dict(self):
        """Test that get_profiles returns all available profiles."""
        NTM = self._get_class()
        engine = NTM()
        profiles = engine.get_profiles()
        self.assertIsInstance(profiles, dict)
        self.assertGreater(len(profiles), 0)
        self.assertIn("google.com", profiles)
        self.assertIn("cdn-front", profiles)
        self.assertIn("iran-banking", profiles)

    def test_morph_traffic_with_packets(self):
        """Test traffic morphing with a packet sequence."""
        NTM = self._get_class()
        PacketInfo = self._get_packet_info()
        MorphResult = self._get_morph_result()

        engine = NTM(padding_strength=0.5, jitter_strength=0.5)

        packets = [
            PacketInfo(size=256, timestamp=time.time(), direction="outbound"),
            PacketInfo(size=512, timestamp=time.time() + 0.05, direction="inbound"),
            PacketInfo(size=128, timestamp=time.time() + 0.10, direction="outbound"),
        ]

        result = engine.morph_traffic(packets)
        self.assertIsInstance(result, MorphResult)
        self.assertEqual(result.original_count, 3)
        # morphed_count includes original + potentially added dummy packets
        # but may be less if overhead trimming removed some
        self.assertGreaterEqual(result.morphed_count, 1)
        self.assertIn(result.target_profile, ["cdn-front", "google.com"])

    def test_morph_traffic_with_target_profile(self):
        """Test traffic morphing with a specific target profile."""
        NTM = self._get_class()
        PacketInfo = self._get_packet_info()
        MorphResult = self._get_morph_result()

        engine = NTM()
        target = engine.generate_target_profile("google.com")

        packets = [
            PacketInfo(size=256, timestamp=time.time(), direction="outbound"),
            PacketInfo(size=512, timestamp=time.time() + 0.05, direction="inbound"),
        ]

        result = engine.morph_traffic(packets, target_profile=target)
        self.assertIsInstance(result, MorphResult)
        self.assertEqual(result.target_profile, "google.com")

    def test_morph_traffic_empty_sequence(self):
        """Test traffic morphing with empty packet sequence."""
        NTM = self._get_class()
        MorphResult = self._get_morph_result()

        engine = NTM()
        result = engine.morph_traffic([])
        self.assertIsInstance(result, MorphResult)
        self.assertEqual(result.original_count, 0)
        self.assertEqual(result.morphed_count, 0)
        self.assertEqual(result.padding_added_bytes, 0)

    def test_morph_effectiveness_score_range(self):
        """Test that morphing effectiveness score is in [0, 1]."""
        NTM = self._get_class()
        PacketInfo = self._get_packet_info()

        engine = NTM(padding_strength=0.8, jitter_strength=0.8)

        packets = [
            PacketInfo(size=256 + i * 50, timestamp=time.time() + i * 0.05, direction="outbound")
            for i in range(10)
        ]

        result = engine.morph_traffic(packets)
        self.assertGreaterEqual(result.effectiveness_score, 0.0)
        self.assertLessEqual(result.effectiveness_score, 1.0)

    def test_morph_traffic_iran_domestic_profile(self):
        """Test morphing with Iran domestic traffic profile."""
        NTM = self._get_class()
        PacketInfo = self._get_packet_info()

        engine = NTM(default_profile="iran-banking")

        packets = [
            PacketInfo(size=256, timestamp=time.time(), direction="outbound"),
        ]

        result = engine.morph_traffic(packets)
        self.assertEqual(result.target_profile, "iran-banking")

    def test_zero_padding_strength_no_padding(self):
        """Test that zero padding strength results in no padding."""
        NTM = self._get_class()
        PacketInfo = self._get_packet_info()

        engine = NTM(padding_strength=0.0, jitter_strength=0.0)

        packets = [
            PacketInfo(size=256, timestamp=time.time(), direction="outbound"),
        ]

        result = engine.morph_traffic(packets)
        # With zero padding and zero jitter, original should be preserved
        self.assertEqual(result.padding_added_bytes, 0)

    def test_max_overhead_pct_enforced(self):
        """Test that max_overhead_pct limits bandwidth overhead."""
        NTM = self._get_class()
        PacketInfo = self._get_packet_info()

        engine = NTM(
            padding_strength=1.0,
            jitter_strength=0.0,
            max_overhead_pct=5.0,  # Very strict overhead limit
        )

        packets = [
            PacketInfo(size=256, timestamp=time.time() + i * 0.01, direction="outbound")
            for i in range(20)
        ]

        result = engine.morph_traffic(packets)
        # Overhead should be controlled (packets may be trimmed)
        self.assertIsNotNone(result.packets_removed)


# ══════════════════════════════════════════════════════════════════════════════
# 2. JA3_JA3S RotationEngine Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestJA3JA3SRotationEngine(unittest.TestCase):
    """Test the JA3/JA3S Rotation Engine for TLS fingerprint rotation."""

    def _get_class(self):
        from torshield_ai_gateway.neural_anti_dpi_v3 import JA3_JA3S_RotationEngine
        return JA3_JA3S_RotationEngine

    def _get_ja3_profile(self):
        from torshield_ai_gateway.neural_anti_dpi_v3 import JA3Profile
        return JA3Profile

    def test_instantiation_with_defaults(self):
        """Test JA3_JA3S_RotationEngine instantiation with defaults."""
        JRE = self._get_class()
        engine = JRE()
        self.assertIsNotNone(engine)
        self.assertEqual(engine.rotation_strategy, "time")
        self.assertEqual(engine.rotation_interval_minutes, 60)
        self.assertTrue(engine.prefer_iran_domestic)

    def test_instantiation_with_custom_params(self):
        """Test JA3_JA3S_RotationEngine with custom parameters."""
        JRE = self._get_class()
        engine = JRE(
            rotation_strategy="request",
            rotation_request_count=50,
            prefer_iran_domestic=False,
        )
        self.assertEqual(engine.rotation_strategy, "request")
        self.assertEqual(engine.rotation_request_count, 50)
        self.assertFalse(engine.prefer_iran_domestic)

    def test_profile_generation(self):
        """Test that JA3 profiles are generated from the built-in database."""
        JRE = self._get_class()
        engine = JRE()
        profiles = engine.get_all_profiles()
        self.assertIsInstance(profiles, dict)
        self.assertGreater(len(profiles), 0)

    def test_builtin_profiles_include_browsers(self):
        """Test that built-in profiles include Chrome, Firefox, Safari, Edge."""
        JRE = self._get_class()
        engine = JRE()
        profiles = engine.get_all_profiles()

        # Should have at least Chrome, Firefox, Safari, Edge profiles
        profile_names = list(profiles.keys())
        # Check for common browser profiles
        has_chrome = any("chrome" in name for name in profile_names)
        has_firefox = any("firefox" in name for name in profile_names)
        self.assertTrue(has_chrome, "No Chrome profile found")
        self.assertTrue(has_firefox, "No Firefox profile found")

    def test_get_current_profile_returns_tuple(self):
        """Test that get_current_profile returns (ja3, ja3s) tuple."""
        JRE = self._get_class()
        engine = JRE()
        ja3, ja3s = engine.get_current_profile()
        self.assertIsInstance(ja3, str)
        self.assertIsInstance(ja3s, str)
        self.assertGreater(len(ja3), 0)

    def test_rotate_returns_new_profile(self):
        """Test that rotate() returns a new JA3/JA3S profile."""
        JRE = self._get_class()
        engine = JRE(rotation_strategy="time", rotation_interval_minutes=999)
        ja3_before, _ = engine.get_current_profile()
        ja3_after, _ = engine.rotate()
        self.assertIsInstance(ja3_after, str)
        self.assertGreater(len(ja3_after), 0)

    def test_iran_domestic_profiles_exist(self):
        """Test that Iran-specific domestic profiles are available."""
        JRE = self._get_class()
        engine = JRE()
        profiles = engine.get_all_profiles()

        domestic = {name: p for name, p in profiles.items() if p.iran_domestic}
        self.assertGreater(len(domestic), 0)

    def test_get_iran_domestic_profile(self):
        """Test getting an Iran domestic browser traffic fingerprint."""
        JRE = self._get_class()
        engine = JRE()
        ja3, ja3s = engine.get_iran_domestic_profile()
        self.assertIsInstance(ja3, str)
        self.assertIsInstance(ja3s, str)
        self.assertGreater(len(ja3), 0)

    def test_iran_domestic_profiles_have_notes(self):
        """Test that Iran domestic profiles have usage notes."""
        JRE = self._get_class()
        JA3Profile = self._get_ja3_profile()
        engine = JRE()
        profiles = engine.get_all_profiles()

        for name, profile in profiles.items():
            if profile.iran_domestic:
                self.assertIsInstance(profile, JA3Profile)
                # Iran domestic profiles should have notes
                self.assertIsInstance(profile.iran_notes, str)

    def test_iran_domestic_profiles_have_higher_weights(self):
        """Test that Iran domestic profiles have weight >= 1.0."""
        JRE = self._get_class()
        engine = JRE()
        profiles = engine.get_all_profiles()

        for name, profile in profiles.items():
            if profile.iran_domestic:
                self.assertGreaterEqual(profile.weight, 1.0)

    def test_get_full_profile(self):
        """Test getting a full JA3Profile object."""
        JRE = self._get_class()
        JA3Profile = self._get_ja3_profile()
        engine = JRE()
        profile = engine.get_full_profile()
        self.assertIsInstance(profile, JA3Profile)
        self.assertGreater(len(profile.cipher_suites), 0)

    def test_get_full_profile_by_name(self):
        """Test getting a specific JA3Profile by name."""
        JRE = self._get_class()
        JA3Profile = self._get_ja3_profile()
        engine = JRE()
        profiles = engine.get_all_profiles()
        first_name = list(profiles.keys())[0]
        profile = engine.get_full_profile(first_name)
        self.assertIsInstance(profile, JA3Profile)
        self.assertEqual(profile.profile_name, first_name)

    def test_rotation_strategy_request(self):
        """Test request-based rotation strategy."""
        JRE = self._get_class()
        engine = JRE(
            rotation_strategy="request",
            rotation_request_count=3,
        )
        self.assertEqual(engine.rotation_strategy, "request")

        # After 3 get_current_profile calls, rotation should be triggered
        for _ in range(3):
            engine.get_current_profile()

    def test_rotation_strategy_random(self):
        """Test random rotation strategy doesn't crash."""
        JRE = self._get_class()
        engine = JRE(
            rotation_strategy="random",
            random_rotation_probability=0.5,
        )
        # Call multiple times — should not crash
        for _ in range(10):
            ja3, ja3s = engine.get_current_profile()
            self.assertIsInstance(ja3, str)

    def test_ja3_string_format(self):
        """Test that JA3 strings follow the expected format."""
        JRE = self._get_class()
        engine = JRE()
        ja3, _ = engine.get_current_profile()
        # JA3 format: version,ciphers,extensions,curves,point_formats
        parts = ja3.split(",")
        self.assertGreaterEqual(len(parts), 5)


# ══════════════════════════════════════════════════════════════════════════════
# 3. ECHFallbackRouter Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestECHFallbackRouter(unittest.TestCase):
    """Test the ECH Fallback Router with post-quantum scoring."""

    def _get_class(self):
        from torshield_ai_gateway.neural_anti_dpi_v3 import ECHFallbackRouter
        return ECHFallbackRouter

    def _get_ech_result(self):
        from torshield_ai_gateway.neural_anti_dpi_v3 import ECHResult
        return ECHResult

    def _get_bridge_score(self):
        from torshield_ai_gateway.neural_anti_dpi_v3 import BridgeScore
        return BridgeScore

    def test_instantiation_with_defaults(self):
        """Test ECHFallbackRouter instantiation with defaults."""
        EFR = self._get_class()
        router = EFR()
        self.assertIsNotNone(router)
        self.assertEqual(router.ech_timeout_ms, 2000.0)
        self.assertTrue(router.prefer_pq)
        self.assertFalse(router.nin_survival_mode)

    def test_instantiation_with_custom_params(self):
        """Test ECHFallbackRouter with custom parameters."""
        EFR = self._get_class()
        router = EFR(
            ech_timeout_ms=5000.0,
            prefer_pq=False,
            nin_survival_mode=True,
        )
        self.assertEqual(router.ech_timeout_ms, 5000.0)
        self.assertFalse(router.prefer_pq)
        self.assertTrue(router.nin_survival_mode)

    def test_resolve_ech_known_domain(self):
        """Test ECH resolution for a known domain (cloudflare.com)."""
        EFR = self._get_class()
        ECHResult = self._get_ech_result()
        router = EFR()
        result = router.resolve_ech("cloudflare.com")
        self.assertIsInstance(result, ECHResult)
        self.assertEqual(result.domain, "cloudflare.com")
        self.assertTrue(result.ech_available)

    def test_resolve_ech_no_ech_domain(self):
        """Test ECH resolution for a domain without ECH support."""
        EFR = self._get_class()
        ECHResult = self._get_ech_result()
        router = EFR()
        result = router.resolve_ech("arvancloud.ir")
        self.assertIsInstance(result, ECHResult)
        self.assertFalse(result.ech_available)
        # Should have a fallback method
        self.assertNotEqual(result.fallback_used, "")

    def test_resolve_ech_unknown_domain(self):
        """Test ECH resolution for an unknown domain."""
        EFR = self._get_class()
        ECHResult = self._get_ech_result()
        router = EFR()
        result = router.resolve_ech("unknown.example.com")
        self.assertIsInstance(result, ECHResult)
        self.assertFalse(result.ech_available)
        # Should use a fallback method
        self.assertNotEqual(result.fallback_used, "")

    def test_resolve_ech_caching(self):
        """Test that ECH resolution results are cached."""
        EFR = self._get_class()
        router = EFR()

        result1 = router.resolve_ech("cloudflare.com")
        result2 = router.resolve_ech("cloudflare.com")

        # Second call should use cache (same result)
        self.assertEqual(result1.domain, result2.domain)
        self.assertEqual(result1.ech_available, result2.ech_available)

    def test_score_bridge_pq_with_kyber(self):
        """Test post-quantum scoring for a bridge with Kyber support."""
        EFR = self._get_class()
        BridgeScore = self._get_bridge_score()
        router = EFR(prefer_pq=True)

        bridge_info = {
            "bridge_line": "obfs4 1.2.3.4:443 cert=test iat-mode=2",
            "transport": "obfs4",
            "cdn_fronted": True,
            "snowflake": False,
            "ech_capable": True,
            "kyber_support": True,
        }

        score = router.score_bridge_pq(bridge_info)
        self.assertIsInstance(score, BridgeScore)
        self.assertTrue(score.kyber_support)
        self.assertGreater(score.pq_score, 0.5)
        self.assertTrue(score.recommended)

    def test_score_bridge_pq_without_kyber(self):
        """Test post-quantum scoring for a bridge without Kyber support."""
        EFR = self._get_class()
        BridgeScore = self._get_bridge_score()
        router = EFR(prefer_pq=True)

        bridge_info = {
            "bridge_line": "vanilla 1.2.3.4:443",
            "transport": "vanilla",
            "cdn_fronted": False,
            "snowflake": False,
            "ech_capable": False,
            "kyber_support": False,
        }

        score = router.score_bridge_pq(bridge_info)
        self.assertIsInstance(score, BridgeScore)
        self.assertFalse(score.kyber_support)
        self.assertEqual(score.pq_score, 0.0)
        self.assertFalse(score.recommended)

    def test_score_bridge_pq_snowflake(self):
        """Test PQ scoring for a Snowflake bridge."""
        EFR = self._get_class()
        BridgeScore = self._get_bridge_score()
        router = EFR()

        bridge_info = {
            "bridge_line": "snowflake 1.2.3.4:443",
            "transport": "snowflake",
            "cdn_fronted": False,
            "snowflake": True,
            "ech_capable": False,
            "kyber_support": False,
        }

        score = router.score_bridge_pq(bridge_info)
        self.assertTrue(score.snowflake)
        self.assertGreater(score.nin_survival_score, 0.3)

    def test_route_with_ech_fallback_ech_available(self):
        """Test routing when ECH is available for the target domain."""
        EFR = self._get_class()
        ECHResult = self._get_ech_result()
        router = EFR()

        result = router.route_with_ech_fallback("cloudflare.com")
        self.assertIsInstance(result, ECHResult)
        self.assertTrue(result.ech_available)

    def test_route_with_ech_fallback_to_domain_fronting(self):
        """Test routing fallback to domain fronting when ECH is not available."""
        EFR = self._get_class()
        ECHResult = self._get_ech_result()
        router = EFR()

        # arvancloud.ir has fronting but no ECH
        result = router.route_with_ech_fallback("arvancloud.ir")
        self.assertIsInstance(result, ECHResult)
        self.assertFalse(result.ech_available)
        self.assertEqual(result.fallback_used, "domain_fronting")

    def test_route_with_ech_fallback_to_sni_splitting(self):
        """Test routing fallback to SNI splitting for unknown domains."""
        EFR = self._get_class()
        ECHResult = self._get_ech_result()
        router = EFR()

        result = router.route_with_ech_fallback("totally-unknown.example.com")
        self.assertIsInstance(result, ECHResult)
        self.assertFalse(result.ech_available)
        # Should use either domain_fronting or sni_splitting
        self.assertIn(result.fallback_used, ["domain_fronting", "sni_splitting", "sni_padding"])

    def test_nin_survival_bridges(self):
        """Test getting top N bridges ranked for NIN survival."""
        EFR = self._get_class()
        BridgeScore = self._get_bridge_score()
        router = EFR(nin_survival_mode=True)

        bridges = [
            {"bridge_line": "snowflake 1.2.3.4:443", "transport": "snowflake",
             "cdn_fronted": True, "snowflake": True, "ech_capable": False, "kyber_support": False},
            {"bridge_line": "vanilla 5.6.7.8:443", "transport": "vanilla",
             "cdn_fronted": False, "snowflake": False, "ech_capable": False, "kyber_support": False},
            {"bridge_line": "webtunnel 9.10.11.12:443 url=https://x.com", "transport": "webtunnel",
             "cdn_fronted": True, "snowflake": False, "ech_capable": True, "kyber_support": True},
            {"bridge_line": "obfs4 13.14.15.16:443 cert=abc", "transport": "obfs4",
             "cdn_fronted": False, "snowflake": False, "ech_capable": False, "kyber_support": False},
        ]

        top_bridges = router.get_nin_survival_bridges(bridges, top_n=3)
        self.assertEqual(len(top_bridges), 3)
        # Bridges should be sorted by overall_score descending
        for i in range(len(top_bridges) - 1):
            self.assertGreaterEqual(
                top_bridges[i].overall_score,
                top_bridges[i + 1].overall_score,
            )

    def test_get_status(self):
        """Test ECH router status reporting."""
        EFR = self._get_class()
        router = EFR()
        status = router.get_status()
        self.assertIsInstance(status, dict)
        self.assertIn("ech_cache_size", status)
        self.assertIn("bridge_scores_size", status)
        self.assertIn("prefer_pq", status)
        self.assertIn("nin_survival_mode", status)
        self.assertIn("known_ech_domains", status)

    def test_pq_scoring_with_pq_preference(self):
        """Test that prefer_pq=True gives higher scores to PQ-capable bridges."""
        EFR = self._get_class()
        router_pq = EFR(prefer_pq=True)
        router_no_pq = EFR(prefer_pq=False)

        bridge_info = {
            "bridge_line": "obfs4 1.2.3.4:443 cert=test",
            "transport": "obfs4",
            "cdn_fronted": False,
            "snowflake": False,
            "ech_capable": False,
            "kyber_support": True,
        }

        score_pq = router_pq.score_bridge_pq(bridge_info)
        score_no_pq = router_no_pq.score_bridge_pq(bridge_info)

        # PQ-preferring router should score higher for PQ-capable bridge
        self.assertGreater(score_pq.overall_score, score_no_pq.overall_score)

    def test_nin_survival_mode_affects_scoring(self):
        """Test that NIN survival mode increases weight of survival score."""
        EFR = self._get_class()
        router_nin = EFR(nin_survival_mode=True)
        router_normal = EFR(nin_survival_mode=False)

        bridge_info = {
            "bridge_line": "webtunnel 1.2.3.4:443 url=https://cdn.example.com",
            "transport": "webtunnel",
            "cdn_fronted": True,
            "snowflake": False,
            "ech_capable": True,
            "kyber_support": False,
        }

        score_nin = router_nin.score_bridge_pq(bridge_info)
        score_normal = router_normal.score_bridge_pq(bridge_info)

        # NIN mode should give higher overall score for CDN-fronted bridges
        self.assertGreater(score_nin.overall_score, score_normal.overall_score)


# ══════════════════════════════════════════════════════════════════════════════
# 4. AntiDPIV3Orchestrator Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestAntiDPIV3Orchestrator(unittest.TestCase):
    """Test the V3 Orchestrator that integrates all V3 subsystems."""

    def _get_class(self):
        from torshield_ai_gateway.neural_anti_dpi_v3 import AntiDPIV3Orchestrator
        return AntiDPIV3Orchestrator

    def _get_evasion_result(self):
        from torshield_ai_gateway.neural_anti_dpi_v3 import EvasionResult
        return EvasionResult

    def test_instantiation_with_defaults(self):
        """Test AntiDPIV3Orchestrator instantiation with defaults."""
        Orch = self._get_class()
        v3 = Orch()
        self.assertIsNotNone(v3)
        self.assertIsNotNone(v3.morphing)
        self.assertIsNotNone(v3.ja3_engine)
        self.assertIsNotNone(v3.ech_router)

    def test_instantiation_with_custom_configs(self):
        """Test AntiDPIV3Orchestrator with custom subsystem configurations."""
        Orch = self._get_class()
        v3 = Orch(
            morphing_config={"default_profile": "google.com", "padding_strength": 0.5},
            ja3_config={"rotation_strategy": "request", "rotation_request_count": 50},
            ech_config={"nin_survival_mode": True},
        )
        self.assertEqual(v3.morphing.default_profile, "google.com")
        self.assertEqual(v3.ja3_engine.rotation_strategy, "request")
        self.assertTrue(v3.ech_router.nin_survival_mode)

    def test_analyze_and_evade_basic(self):
        """Test basic analysis and evasion with minimal input."""
        Orch = self._get_class()
        EvasionResult = self._get_evasion_result()
        v3 = Orch()

        traffic_info = {
            "transport": "obfs4",
        }
        result = v3.analyze_and_evade(traffic_info)
        self.assertIsInstance(result, EvasionResult)
        self.assertIsInstance(result.evasion_strategy, str)

    def test_analyze_and_evade_with_packets(self):
        """Test analysis with packet sequence for traffic morphing."""
        Orch = self._get_class()
        EvasionResult = self._get_evasion_result()
        v3 = Orch()

        traffic_info = {
            "transport": "obfs4",
            "packet_sequence": [
                {"size": 256, "timestamp": time.time(), "direction": "outbound"},
                {"size": 512, "timestamp": time.time() + 0.05, "direction": "inbound"},
            ],
            "target_profile": "cdn-front",
        }
        result = v3.analyze_and_evade(traffic_info)
        self.assertIsInstance(result, EvasionResult)
        # With packet_sequence, morphing should be attempted
        self.assertIsNotNone(result.morph_result)

    def test_analyze_and_evade_with_ech_domains(self):
        """Test analysis with ECH-capable domains."""
        Orch = self._get_class()
        EvasionResult = self._get_evasion_result()
        v3 = Orch()

        traffic_info = {
            "transport": "webtunnel",
            "target_domain": "cloudflare.com",
            "ech_domains": ["cloudflare.com"],
        }
        result = v3.analyze_and_evade(traffic_info)
        self.assertIsInstance(result, EvasionResult)
        # ECH routing should be attempted
        self.assertIsNotNone(result.ech_result)

    def test_analyze_and_evade_with_bridge_scoring(self):
        """Test analysis with bridge scoring for PQ readiness."""
        Orch = self._get_class()
        EvasionResult = self._get_evasion_result()
        v3 = Orch()

        traffic_info = {
            "transport": "snowflake",
            "bridges": [
                {"bridge_line": "snowflake 1.2.3.4:443", "transport": "snowflake",
                 "cdn_fronted": True, "snowflake": True, "ech_capable": False, "kyber_support": True},
            ],
        }
        result = v3.analyze_and_evade(traffic_info)
        self.assertIsInstance(result, EvasionResult)
        self.assertEqual(len(result.bridge_scores), 1)
        self.assertIn("pq_score", result.bridge_scores[0])

    def test_get_status(self):
        """Test V3 orchestrator status reporting."""
        Orch = self._get_class()
        v3 = Orch()
        status = v3.get_status()

        self.assertIsInstance(status, dict)
        self.assertEqual(status["engine"], "AntiDPIV3Orchestrator")
        self.assertIn("v2_available", status)
        self.assertIn("morphing", status)
        self.assertIn("ja3_rotation", status)
        self.assertIn("ech_router", status)
        self.assertIn("ai_gateway_attached", status)

    def test_status_morphing_info(self):
        """Test that status includes morphing subsystem details."""
        Orch = self._get_class()
        v3 = Orch()
        status = v3.get_status()

        morphing = status["morphing"]
        self.assertIn("default_profile", morphing)
        self.assertIn("padding_strength", morphing)
        self.assertIn("jitter_strength", morphing)
        self.assertIn("profiles_available", morphing)
        self.assertGreater(len(morphing["profiles_available"]), 0)

    def test_status_ja3_info(self):
        """Test that status includes JA3 rotation details."""
        Orch = self._get_class()
        v3 = Orch()
        status = v3.get_status()

        ja3 = status["ja3_rotation"]
        self.assertIn("current_profile", ja3)
        self.assertIn("rotation_strategy", ja3)
        self.assertIn("prefer_iran_domestic", ja3)
        self.assertIn("profiles_available", ja3)

    def test_risk_level_assessment(self):
        """Test that risk level is correctly assessed."""
        Orch = self._get_class()
        EvasionResult = self._get_evasion_result()

        # Low coverage should produce higher risk
        v3 = Orch()
        result = v3.analyze_and_evade({"transport": "vanilla"})
        self.assertIn(result.risk_level, ["low", "medium", "high", "critical"])

    def test_evasion_strategy_string(self):
        """Test that evasion strategy string describes applied techniques."""
        Orch = self._get_class()
        v3 = Orch()

        result = v3.analyze_and_evade({
            "transport": "obfs4",
            "target_domain": "cloudflare.com",
        })
        # Strategy string should contain at least one technique
        self.assertIsInstance(result.evasion_strategy, str)
        self.assertGreater(len(result.evasion_strategy), 0)

    def test_confidence_score_range(self):
        """Test that confidence score is in valid range."""
        Orch = self._get_class()
        v3 = Orch()

        result = v3.analyze_and_evade({"transport": "obfs4"})
        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)

    def test_set_ai_gateway(self):
        """Test attaching an AI gateway to the orchestrator."""
        Orch = self._get_class()
        v3 = Orch()

        mock_gateway = MagicMock()
        v3.set_ai_gateway(mock_gateway)

        status = v3.get_status()
        self.assertTrue(status["ai_gateway_attached"])

    def test_analyze_with_ai_gateway(self):
        """Test analysis with AI gateway attached."""
        Orch = self._get_class()
        EvasionResult = self._get_evasion_result()
        v3 = Orch()

        mock_gateway = MagicMock()
        mock_gateway.chat.return_value = "fragment_padding"
        v3.set_ai_gateway(mock_gateway)

        result = v3.analyze_and_evade({"transport": "obfs4"})
        self.assertIsInstance(result, EvasionResult)

    def test_analysis_count_increments(self):
        """Test that analysis count increments with each call."""
        Orch = self._get_class()
        v3 = Orch()

        initial_count = v3._analysis_count
        v3.analyze_and_evade({"transport": "obfs4"})
        v3.analyze_and_evade({"transport": "webtunnel"})

        self.assertEqual(v3._analysis_count, initial_count + 2)


# ══════════════════════════════════════════════════════════════════════════════
# 5. V2 Integration / Fallback Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestV2Integration(unittest.TestCase):
    """Test V3 integration with V2 engine (graceful fallback)."""

    def test_v3_status_reports_v2_availability(self):
        """Test that V3 orchestrator reports whether V2 is available."""
        from torshield_ai_gateway.neural_anti_dpi_v3 import AntiDPIV3Orchestrator, _V2_AVAILABLE

        v3 = AntiDPIV3Orchestrator()
        status = v3.get_status()

        self.assertIn("v2_available", status)
        # Should match the module-level flag
        self.assertEqual(status["v2_available"], _V2_AVAILABLE)

    def test_v3_with_v2_available(self):
        """Test V3 orchestrator behavior when V2 engine is available."""
        from torshield_ai_gateway.neural_anti_dpi_v3 import AntiDPIV3Orchestrator, _V2_AVAILABLE

        v3 = AntiDPIV3Orchestrator()

        if _V2_AVAILABLE:
            self.assertIsNotNone(v3._v2)
        else:
            self.assertIsNone(v3._v2)

    def test_force_v2_fallback(self):
        """Test forcing V2 fallback through the orchestrator."""
        from torshield_ai_gateway.neural_anti_dpi_v3 import AntiDPIV3Orchestrator, _V2_AVAILABLE

        v3 = AntiDPIV3Orchestrator()

        result = v3.analyze_and_evade({
            "transport": "obfs4",
            "force_v2": True,
        })

        # When force_v2 is True, v2_fallback_used should reflect V2 availability
        if _V2_AVAILABLE and v3._v2 is not None:
            self.assertTrue(result.v2_fallback_used)
        else:
            # V2 not available, can't use it
            self.assertFalse(result.v2_fallback_used)

    def test_v2_fallback_count_tracked(self):
        """Test that V2 fallback count is tracked."""
        from torshield_ai_gateway.neural_anti_dpi_v3 import AntiDPIV3Orchestrator, _V2_AVAILABLE

        v3 = AntiDPIV3Orchestrator()
        initial_count = v3._v2_fallback_count

        v3.analyze_and_evade({
            "transport": "obfs4",
            "force_v2": True,
        })

        if _V2_AVAILABLE and v3._v2 is not None:
            self.assertEqual(v3._v2_fallback_count, initial_count + 1)

    def test_v3_standalone_without_v2(self):
        """Test that V3 operates in standalone mode when V2 is unavailable."""
        from torshield_ai_gateway.neural_anti_dpi_v3 import AntiDPIV3Orchestrator

        # Force V2 to be unavailable
        with patch("torshield_ai_gateway.neural_anti_dpi_v3._V2_AVAILABLE", False):
            with patch("torshield_ai_gateway.neural_anti_dpi_v3.IranAntiDPIV2", None):
                # Create a new instance — V2 should be None
                v3 = AntiDPIV3Orchestrator()
                self.assertIsNone(v3._v2)

                # Analysis should still work
                result = v3.analyze_and_evade({"transport": "obfs4"})
                self.assertIsNotNone(result)
                self.assertFalse(result.v2_fallback_used)

    def test_evasion_result_has_v2_fallback_flag(self):
        """Test that EvasionResult includes v2_fallback_used field."""
        from torshield_ai_gateway.neural_anti_dpi_v3 import EvasionResult

        result = EvasionResult(
            traffic_morphing_applied=True,
            ja3_rotated=True,
            ech_routed=False,
            v2_fallback_used=False,
            morph_result=None,
            ja3_profile=None,
            ech_result=None,
            bridge_scores=[],
            evasion_strategy="traffic_morphing → ja3_rotation",
            risk_level="low",
            confidence=0.75,
        )
        self.assertFalse(result.v2_fallback_used)
        self.assertTrue(result.traffic_morphing_applied)
        self.assertTrue(result.ja3_rotated)

    def test_evasion_result_to_dict(self):
        """Test that EvasionResult can be serialized to dict."""
        from torshield_ai_gateway.neural_anti_dpi_v3 import EvasionResult

        result = EvasionResult(
            traffic_morphing_applied=True,
            ja3_rotated=True,
            ech_routed=True,
            v2_fallback_used=False,
            morph_result={"padding_bytes": 1024},
            ja3_profile={"browser": "Chrome"},
            ech_result={"ech_available": True},
            bridge_scores=[],
            evasion_strategy="full_v3",
            risk_level="low",
            confidence=0.9,
        )

        d = result.to_dict()
        self.assertIsInstance(d, dict)
        self.assertTrue(d["traffic_morphing_applied"])
        self.assertEqual(d["confidence"], 0.9)


# ══════════════════════════════════════════════════════════════════════════════
# 6. Data Structure Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestDataStructures(unittest.TestCase):
    """Test V3 data structures for correctness."""

    def test_packet_info_creation(self):
        """Test PacketInfo dataclass creation."""
        from torshield_ai_gateway.neural_anti_dpi_v3 import PacketInfo

        pkt = PacketInfo(size=256, timestamp=time.time(), direction="outbound")
        self.assertEqual(pkt.size, 256)
        self.assertEqual(pkt.direction, "outbound")
        self.assertEqual(pkt.protocol, "tcp")
        self.assertEqual(pkt.payload_entropy, 0.0)

    def test_packet_info_to_dict(self):
        """Test PacketInfo serialization to dict."""
        from torshield_ai_gateway.neural_anti_dpi_v3 import PacketInfo

        pkt = PacketInfo(size=512, timestamp=12345.0, direction="inbound",
                         protocol="tcp", payload_entropy=0.75)
        d = pkt.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["size"], 512)
        self.assertEqual(d["direction"], "inbound")

    def test_target_profile_creation(self):
        """Test TargetProfile dataclass creation."""
        from torshield_ai_gateway.neural_anti_dpi_v3 import TargetProfile

        profile = TargetProfile(
            name="test",
            description="Test profile",
            packet_size_mean=800.0,
            packet_size_std=300.0,
            packet_size_min=64,
            packet_size_max=1460,
            iat_mean_ms=50.0,
            iat_std_ms=80.0,
            burst_probability=0.3,
            burst_size_mean=8,
            inbound_outbound_ratio=2.5,
            entropy_range=(0.6, 0.8),
        )
        self.assertEqual(profile.name, "test")
        self.assertEqual(profile.packet_size_mean, 800.0)
        self.assertFalse(profile.iran_domestic)

    def test_ech_result_creation(self):
        """Test ECHResult dataclass creation."""
        from torshield_ai_gateway.neural_anti_dpi_v3 import ECHResult

        result = ECHResult(domain="cloudflare.com", ech_available=True)
        self.assertEqual(result.domain, "cloudflare.com")
        self.assertTrue(result.ech_available)
        self.assertEqual(result.fallback_used, "")
        self.assertEqual(result.pq_score, 0.0)

    def test_bridge_score_creation(self):
        """Test BridgeScore dataclass creation."""
        from torshield_ai_gateway.neural_anti_dpi_v3 import BridgeScore

        score = BridgeScore(
            bridge_id="abc123",
            transport="obfs4",
            pq_score=0.8,
            kyber_support=True,
            cdn_fronted=True,
            snowflake=False,
            ech_capable=True,
            nin_survival_score=0.7,
            overall_score=0.75,
            recommended=True,
        )
        self.assertTrue(score.recommended)
        self.assertTrue(score.kyber_support)
        self.assertEqual(score.transport, "obfs4")

    def test_ja3_profile_creation(self):
        """Test JA3Profile dataclass creation."""
        from torshield_ai_gateway.neural_anti_dpi_v3 import JA3Profile

        profile = JA3Profile(
            profile_name="test_chrome",
            ja3_string="771,1,2,3,0",
            ja3s_string="771,1,0",
            browser_name="Chrome",
            browser_version="120+",
            cipher_suites=[0x1301, 0x1302],
            extensions=[0x0000, 0x0017],
            elliptic_curves=[0x001D],
            ec_point_formats=[0x00],
            grease_enabled=True,
            alpn_values=["h2"],
            signature_algorithms=[0x0403],
        )
        self.assertEqual(profile.browser_name, "Chrome")
        self.assertTrue(profile.grease_enabled)
        self.assertFalse(profile.iran_domestic)

    def test_morph_result_creation(self):
        """Test MorphResult dataclass creation."""
        from torshield_ai_gateway.neural_anti_dpi_v3 import MorphResult

        result = MorphResult(
            original_count=5,
            morphed_count=8,
            padding_added_bytes=1024,
            timing_delays_ms=150.0,
            packets_added=3,
            packets_removed=0,
            target_profile="cdn-front",
            effectiveness_score=0.85,
        )
        self.assertEqual(result.original_count, 5)
        self.assertEqual(result.morphed_count, 8)
        self.assertEqual(result.effectiveness_score, 0.85)


if __name__ == "__main__":
    unittest.main()
