"""
tests/test_gateway.py — Gateway facade tests

Tests:
  - Provider waterfall (priority order)
  - LocalAIEngine fallback
  - last_response_source tracking
  - Stats tracking
  - Health stats reporting

All tests use unittest.mock to avoid making real API calls.
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, Mock, patch, PropertyMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestTorShieldAIGateway(unittest.TestCase):
    """Test TorShieldAIGateway provider waterfall and fallback."""

    def _create_gateway_with_mock_providers(self, provider_results=None):
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

        # Set up mock providers with specified results
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

    def test_provider_waterfall_priority(self):
        """Test that providers are tried in priority order."""
        gw = self._create_gateway_with_mock_providers({
            "cerebras": "cerebras response",
            "cloudflare_ai_gateway": "cf gateway response",
            "cloudflare_workers_ai": "cf workers response",
            "portkey": "portkey response",
        })

        result = gw.chat(messages=[{"role": "user", "content": "test"}])
        self.assertEqual(result, "cerebras response")
        self.assertEqual(gw._last_response_source, "primary")

    def test_waterfall_falls_through_on_failure(self):
        """Test that gateway falls through providers when one fails."""
        gw = self._create_gateway_with_mock_providers({
            "cerebras": Exception("cerebras down"),
            "cloudflare_ai_gateway": Exception("cf gateway down"),
            "cloudflare_workers_ai": "cf workers response",
            "portkey": "portkey response",
        })

        result = gw.chat(messages=[{"role": "user", "content": "test"}])
        # Should get cf_workers response since cerebras and cf_gateway failed
        self.assertIn(result, ["cf workers response", "portkey response"])
        self.assertEqual(gw._last_response_source, "primary")

    def test_local_fallback_when_all_providers_fail(self):
        """Test LocalAIEngine fallback when all primary providers fail."""
        gw = self._create_gateway_with_mock_providers({
            "cerebras": Exception("down"),
            "cloudflare_ai_gateway": Exception("down"),
            "cloudflare_workers_ai": Exception("down"),
            "portkey": Exception("down"),
        })

        # Mock LocalAIEngine
        with patch("torshield_ai_gateway.gateway.LocalAIEngine") as MockLocalAI:
            mock_engine = MagicMock()
            mock_engine.chat_complete.return_value = "local fallback response"
            MockLocalAI.return_value = mock_engine

            result = gw.chat(messages=[{"role": "user", "content": "test"}])

        self.assertEqual(result, "local fallback response")
        self.assertEqual(gw._last_response_source, "local_fallback")
        self.assertEqual(gw._stats["local_fallback_uses"], 1)

    def test_no_providers_available(self):
        """Test gateway when no providers are configured."""
        gw = self._create_gateway_with_mock_providers({})

        with patch("torshield_ai_gateway.gateway.LocalAIEngine") as MockLocalAI:
            mock_engine = MagicMock()
            mock_engine.chat_complete.return_value = "no providers response"
            MockLocalAI.return_value = mock_engine

            result = gw.chat(messages=[{"role": "user", "content": "test"}])

        self.assertEqual(result, "no providers response")
        self.assertEqual(gw._last_response_source, "local_fallback")
        self.assertEqual(gw._stats["all_primary_failed"], 1)

    def test_last_response_source_primary(self):
        """Test last_response_source tracks primary responses."""
        gw = self._create_gateway_with_mock_providers({
            "cerebras": "primary response",
        })

        gw.chat(messages=[{"role": "user", "content": "test"}])
        self.assertEqual(gw.last_response_source, "primary")

    def test_last_response_source_local_fallback(self):
        """Test last_response_source tracks fallback responses."""
        gw = self._create_gateway_with_mock_providers({
            "cerebras": Exception("down"),
        })

        with patch("torshield_ai_gateway.gateway.LocalAIEngine") as MockLocalAI:
            mock_engine = MagicMock()
            mock_engine.chat_complete.return_value = "local"
            MockLocalAI.return_value = mock_engine
            gw.chat(messages=[{"role": "user", "content": "test"}])

        self.assertEqual(gw.last_response_source, "local_fallback")

    def test_last_response_source_none_initially(self):
        """Test last_response_source is None before any request."""
        gw = self._create_gateway_with_mock_providers({
            "cerebras": "response",
        })
        self.assertIsNone(gw.last_response_source)

    def test_stats_tracking(self):
        """Test that gateway tracks request statistics."""
        gw = self._create_gateway_with_mock_providers({
            "cerebras": "response",
        })

        # First request
        gw.chat(messages=[{"role": "user", "content": "test1"}])
        self.assertEqual(gw._stats["total_requests"], 1)
        self.assertEqual(gw._stats["primary_successes"], 1)

        # Second request
        gw.chat(messages=[{"role": "user", "content": "test2"}])
        self.assertEqual(gw._stats["total_requests"], 2)
        self.assertEqual(gw._stats["primary_successes"], 2)

    def test_stats_fallback_tracking(self):
        """Test stats track fallback usage correctly."""
        gw = self._create_gateway_with_mock_providers({
            "cerebras": Exception("down"),
        })

        with patch("torshield_ai_gateway.gateway.LocalAIEngine") as MockLocalAI:
            mock_engine = MagicMock()
            mock_engine.chat_complete.return_value = "local"
            MockLocalAI.return_value = mock_engine
            gw.chat(messages=[{"role": "user", "content": "test"}])

        self.assertEqual(gw._stats["local_fallback_uses"], 1)
        self.assertEqual(gw._stats["all_primary_failed"], 1)

    def test_provider_attempts_tracking(self):
        """Test that provider attempts are tracked."""
        gw = self._create_gateway_with_mock_providers({
            "cerebras": "cerebras response",
        })

        gw.chat(messages=[{"role": "user", "content": "test"}])
        self.assertIn("cerebras", gw._stats["provider_attempts"])
        self.assertEqual(gw._stats["provider_attempts"]["cerebras"], 1)

    def test_preferred_provider_first(self):
        """Test that preferred_provider is tried first."""
        gw = self._create_gateway_with_mock_providers({
            "cerebras": "cerebras response",
            "portkey": "portkey response",
        })

        result = gw.chat(
            messages=[{"role": "user", "content": "test"}],
            preferred_provider="portkey",
        )
        self.assertEqual(result, "portkey response")

    def test_health_stats(self):
        """Test health_stats returns correct structure."""
        gw = self._create_gateway_with_mock_providers({
            "cerebras": "response",
        })

        gw.chat(messages=[{"role": "user", "content": "test"}])
        stats = gw.health_stats()

        self.assertIn("total_requests", stats)
        self.assertIn("primary_successes", stats)
        self.assertIn("local_fallback_uses", stats)
        self.assertIn("all_primary_failed", stats)
        self.assertIn("primary_success_rate", stats)
        self.assertIn("degraded_rate", stats)
        self.assertIn("provider_attempts", stats)
        self.assertIn("available_providers", stats)

    def test_health_stats_success_rate(self):
        """Test primary_success_rate calculation in health_stats."""
        gw = self._create_gateway_with_mock_providers({
            "cerebras": "response",
        })

        gw.chat(messages=[{"role": "user", "content": "test"}])
        stats = gw.health_stats()
        self.assertEqual(stats["primary_success_rate"], 1.0)

    def test_prompt_method(self):
        """Test the prompt() convenience method."""
        gw = self._create_gateway_with_mock_providers({
            "cerebras": "prompt response",
        })

        result = gw.prompt(system="You are helpful", user="Hello")
        self.assertEqual(result, "prompt response")

    def test_empty_response_treated_as_failure(self):
        """Test that empty responses are treated as failures."""
        gw = self._create_gateway_with_mock_providers({
            "cerebras": "",  # Empty string
            "cloudflare_ai_gateway": "real response",
        })

        result = gw.chat(messages=[{"role": "user", "content": "test"}])
        # Should fall through to next provider
        self.assertEqual(result, "real response")

    def test_local_fallback_ultimate_fallback(self):
        """Test ultimate JSON fallback when LocalAIEngine also fails."""
        gw = self._create_gateway_with_mock_providers({})

        with patch("torshield_ai_gateway.gateway.LocalAIEngine") as MockLocalAI:
            mock_engine = MagicMock()
            mock_engine.chat_complete.side_effect = Exception("local also failed")
            MockLocalAI.return_value = mock_engine

            result = gw.chat(messages=[{"role": "user", "content": "test"}])

        self.assertIn("error", result)
        self.assertIn("degraded", result)


class TestGetGateway(unittest.TestCase):
    """Test the get_gateway singleton factory."""

    def test_get_gateway_returns_instance(self):
        """Test that get_gateway returns a TorShieldAIGateway instance."""
        from torshield_ai_gateway.gateway import TorShieldAIGateway, get_gateway
        # Reset the singleton
        import torshield_ai_gateway.gateway as gw_module
        gw_module._GATEWAY_INSTANCE = None

        with patch.dict(os.environ, {}, clear=False):
            gw = get_gateway()
            self.assertIsInstance(gw, TorShieldAIGateway)

        # Clean up
        gw_module._GATEWAY_INSTANCE = None

    def test_get_gateway_singleton(self):
        """Test that get_gateway returns the same instance."""
        from torshield_ai_gateway.gateway import get_gateway
        import torshield_ai_gateway.gateway as gw_module
        gw_module._GATEWAY_INSTANCE = None

        with patch.dict(os.environ, {}, clear=False):
            gw1 = get_gateway()
            gw2 = get_gateway()
            self.assertIs(gw1, gw2)

        gw_module._GATEWAY_INSTANCE = None


if __name__ == "__main__":
    unittest.main()
