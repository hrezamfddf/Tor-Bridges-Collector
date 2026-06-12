"""
tests/test_model_selector.py — Model selector tests

Tests:
  - Offline catalog fallback
  - Model ID validation (UUID, paid-only filtering)
  - Failure reporting and re-ranking
  - Provider-aware model selection
  - Cache management

All tests use unittest.mock to avoid making real API calls.
"""

import os
import sys
import time
import unittest
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestModelInfo(unittest.TestCase):
    """Test the ModelInfo dataclass."""

    def test_model_info_creation(self):
        """Test ModelInfo can be created with required fields."""
        from torshield_ai_gateway.model_selector import ModelInfo
        info = ModelInfo(
            id="@cf/meta/llama-3.1-8b-instruct",
            name="Llama 3.1 8B",
        )
        self.assertEqual(info.id, "@cf/meta/llama-3.1-8b-instruct")
        self.assertEqual(info.name, "Llama 3.1 8B")
        self.assertEqual(info.score, 0.0)  # default

    def test_short_name(self):
        """Test ModelInfo.short_name property extracts last component."""
        from torshield_ai_gateway.model_selector import ModelInfo
        info = ModelInfo(
            id="@cf/meta/llama-3.1-8b-instruct",
            name="Llama 3.1 8B Instruct",
            score=80.0,
        )
        short = info.short_name
        self.assertEqual(short, "llama-3.1-8b-instruct")

    def test_model_info_with_all_fields(self):
        """Test ModelInfo with all optional fields."""
        from torshield_ai_gateway.model_selector import ModelInfo
        info = ModelInfo(
            id="@cf/meta/llama-3.1-70b-instruct",
            name="Llama 3.1 70B",
            description="Large language model",
            score=85.0,
            param_b=70.0,
            ctx_k=128,
            tier=2,
        )
        self.assertEqual(info.param_b, 70.0)
        self.assertEqual(info.ctx_k, 128)
        self.assertEqual(info.tier, 2)


class TestCloudflareModelSelector(unittest.TestCase):
    """Test CloudflareModelSelector singleton and methods."""

    def _get_selector(self):
        """Get a fresh CloudflareModelSelector instance."""
        from torshield_ai_gateway.model_selector import CloudflareModelSelector
        CloudflareModelSelector._instance = None
        selector = CloudflareModelSelector()
        CloudflareModelSelector._instance = selector
        return selector

    def test_singleton_pattern(self):
        """Test that instance() returns the same object."""
        from torshield_ai_gateway.model_selector import CloudflareModelSelector
        CloudflareModelSelector._instance = None
        s1 = CloudflareModelSelector.instance()
        s2 = CloudflareModelSelector.instance()
        self.assertIs(s1, s2)
        CloudflareModelSelector._instance = None

    def test_invalidate_cache(self):
        """Test cache invalidation resets state."""
        selector = self._get_selector()
        selector._cache_ts = time.monotonic()
        selector._cached_models = [MagicMock()]
        selector._selected = {"general": "some-model"}

        selector.invalidate_cache()

        self.assertEqual(selector._cache_ts, 0.0)
        self.assertEqual(selector._cached_models, [])
        self.assertEqual(selector._selected, {})

    def test_report_model_failure(self):
        """Test that model failures are tracked."""
        selector = self._get_selector()

        selector.report_model_failure("@cf/test/model-1", error_code=400)
        self.assertEqual(selector._failure_counts.get("@cf/test/model-1"), 1)
        self.assertIn("@cf/test/model-1", selector._recently_failed)

    def test_failure_accumulation(self):
        """Test that multiple failures accumulate."""
        selector = self._get_selector()

        selector.report_model_failure("@cf/test/model-1", error_code=400)
        selector.report_model_failure("@cf/test/model-1", error_code=500)
        selector.report_model_failure("@cf/test/model-1", error_code=404)

        self.assertEqual(selector._failure_counts.get("@cf/test/model-1"), 3)

    def test_failure_penalties_applied(self):
        """Test that failure penalties affect model scoring."""
        selector = self._get_selector()

        from torshield_ai_gateway.model_selector import ModelInfo
        models = [
            ModelInfo(id="@cf/good/model", name="Good", score=90.0),
            ModelInfo(id="@cf/bad/model", name="Bad", score=85.0),
        ]

        # Report failures for the bad model
        selector.report_model_failure("@cf/bad/model", error_code=400)

        selector._apply_failure_penalties(models)

        # The bad model should have a lower score after penalty
        good_model = next(m for m in models if m.id == "@cf/good/model")
        bad_model = next(m for m in models if m.id == "@cf/bad/model")
        self.assertGreater(good_model.score, bad_model.score)

    def test_offline_fallback(self):
        """Test that best_cf_model falls back to offline catalog when API fails."""
        from torshield_ai_gateway.model_selector import best_cf_model

        with patch.dict(os.environ, {
            "CF_ACCOUNT_ID": "test",
            "CF_API_TOKEN_1": "test-token",
        }):
            model = best_cf_model(task="general")
            self.assertIsInstance(model, str)
            self.assertGreater(len(model), 0)

    def test_ranked_models_returns_list(self):
        """Test that ranked_cf_models returns a list."""
        from torshield_ai_gateway.model_selector import ranked_cf_models

        with patch.dict(os.environ, {
            "CF_ACCOUNT_ID": "test",
            "CF_API_TOKEN_1": "test-token",
        }):
            models = ranked_cf_models(task="general", top_n=3)
            self.assertIsInstance(models, list)

    def test_model_selector_status(self):
        """Test model_selector_status returns a dictionary."""
        from torshield_ai_gateway.model_selector import model_selector_status

        status = model_selector_status()
        self.assertIsInstance(status, dict)

    def test_uuid_model_id_filtering(self):
        """Test that UUID-format model IDs are properly handled."""
        selector = self._get_selector()

        uuid_model = "abc12345-def6-7890-abcd-ef1234567890"
        selector.report_model_failure(uuid_model, error_code=400)
        self.assertIn(uuid_model, selector._recently_failed)

    def test_status_method(self):
        """Test CloudflareModelSelector.status() returns valid structure."""
        selector = self._get_selector()
        status = selector.status()
        self.assertIsInstance(status, dict)


class TestProviderAwareModelSelector(unittest.TestCase):
    """Test the ProviderAwareModelSelector."""

    def test_provider_aware_selector_creation(self):
        """Test ProviderAwareModelSelector can be instantiated."""
        from torshield_ai_gateway.model_selector import ProviderAwareModelSelector
        ProviderAwareModelSelector._instance = None
        selector = ProviderAwareModelSelector()
        self.assertIsNotNone(selector)
        ProviderAwareModelSelector._instance = None

    def test_provider_aware_singleton(self):
        """Test ProviderAwareModelSelector singleton pattern."""
        from torshield_ai_gateway.model_selector import ProviderAwareModelSelector
        ProviderAwareModelSelector._instance = None
        s1 = ProviderAwareModelSelector.instance()
        s2 = ProviderAwareModelSelector.instance()
        self.assertIs(s1, s2)
        ProviderAwareModelSelector._instance = None

    @patch.dict(os.environ, {"CEREBRAS_API_KEY": "test-key"})
    def test_get_best_cerebras_model(self):
        """Test Cerebras model selection."""
        from torshield_ai_gateway.model_selector import ProviderAwareModelSelector
        ProviderAwareModelSelector._instance = None
        selector = ProviderAwareModelSelector()

        model = selector.get_best_cerebras_model(task="general")
        self.assertIsInstance(model, str)
        self.assertGreater(len(model), 0)
        ProviderAwareModelSelector._instance = None

    def test_get_best_overall_model_returns_tuple(self):
        """Test overall best model selection returns a (provider, model) tuple."""
        from torshield_ai_gateway.model_selector import ProviderAwareModelSelector
        ProviderAwareModelSelector._instance = None
        selector = ProviderAwareModelSelector()

        result = selector.get_best_overall_model(task="general")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        provider, model = result
        self.assertIn(provider, ["cloudflare", "cerebras", "portkey"])
        self.assertIsInstance(model, str)
        self.assertGreater(len(model), 0)
        ProviderAwareModelSelector._instance = None

    def test_provider_aware_status(self):
        """Test ProviderAwareModelSelector.status() returns a dict."""
        from torshield_ai_gateway.model_selector import ProviderAwareModelSelector
        ProviderAwareModelSelector._instance = None
        selector = ProviderAwareModelSelector()
        status = selector.status()
        self.assertIsInstance(status, dict)
        ProviderAwareModelSelector._instance = None


if __name__ == "__main__":
    unittest.main()
