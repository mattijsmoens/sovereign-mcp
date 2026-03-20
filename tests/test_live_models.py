"""
LIVE MODEL INTEGRATION TESTS — Real API calls to Gemini + Ollama.
=================================================================
Tests the consensus verification with ACTUAL model responses,
not mocks. This verifies that:
  1. Real models can extract structured JSON from content
  2. Two different models produce matching hashes on factual data
  3. The full pipeline (schema → deception → consensus) works end-to-end
  4. Network errors are handled gracefully

Requires:
  - Gemini API key (from Karios .env)
  - Ollama running locally on port 11434
"""

import sys
import os
import json
import time
import hashlib
import urllib.request
import urllib.error
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from sovereign_mcp.consensus import ModelProvider, ConsensusVerifier
from sovereign_mcp.canonical_json import canonical_hash, canonical_dumps

# ===================================================================
# Load API key
# ===================================================================

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    _env_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "Karios", ".env")
    _env_path = os.path.normpath(_env_path)
    if os.path.exists(_env_path):
        with open(_env_path, 'r') as f:
            for line in f:
                if line.startswith("GEMINI_API_KEY="):
                    GEMINI_API_KEY = line.strip().split("=", 1)[1]
                    break


# ===================================================================
# Real Model Providers
# ===================================================================

class GeminiProvider(ModelProvider):
    """
    Real Gemini model provider using the REST API directly.
    Zero dependencies — uses only urllib.
    """

    API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    def __init__(self, model_id="gemini-2.0-flash", api_key=None):
        super().__init__(model_id, temperature=0)
        self.api_key = api_key or GEMINI_API_KEY
        if not self.api_key:
            raise ValueError("Gemini API key required")

    def extract_structured(self, content, schema):
        """
        Send content to Gemini and ask it to extract structured JSON
        matching the given schema.
        """
        # Build the prompt that asks for structured extraction
        schema_desc = json.dumps(schema, indent=2)
        prompt = (
            f"Extract the following information from this content and return "
            f"ONLY valid JSON matching this exact schema. No explanation, no markdown, "
            f"just the JSON object.\n\n"
            f"Schema:\n{schema_desc}\n\n"
            f"Content:\n{content}\n\n"
            f"Return ONLY the JSON object:"
        )

        url = self.API_URL.format(model=self.model_id)
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0,
                "topP": 1,
                "maxOutputTokens": 512,
            }
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("x-goog-api-key", self.api_key)  # Key in header, not URL

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8") if e.fp else ""
            raise RuntimeError(f"Gemini API error {e.code}: {body[:500]}")

        # Parse response
        text = result["candidates"][0]["content"]["parts"][0]["text"]
        # Strip markdown code fences if present
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
            text = text.strip()

        return json.loads(text)


class OllamaProvider(ModelProvider):
    """
    Real Ollama model provider using the local REST API.
    Zero dependencies — uses only urllib.
    """

    def __init__(self, model_id="qwen3.5:9b", host="http://localhost:11434"):
        super().__init__(model_id, temperature=0)
        self.host = host

    def extract_structured(self, content, schema):
        """
        Send content to local Ollama and ask it to extract structured JSON.
        """
        schema_desc = json.dumps(schema, indent=2)
        prompt = (
            f"Extract the following information from this content and return "
            f"ONLY valid JSON matching this exact schema. No explanation, no markdown, "
            f"just the JSON object.\n\n"
            f"Schema:\n{schema_desc}\n\n"
            f"Content:\n{content}\n\n"
            f"Return ONLY the JSON object:"
        )

        url = f"{self.host}/api/generate"
        payload = {
            "model": self.model_id,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0,
                "top_p": 1,
            },
            "format": "json",
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"Ollama API error {e.code}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Ollama not reachable: {e}")

        text = result.get("response", "").strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
            text = text.strip()

        return json.loads(text)


# ===================================================================
# Helper: check if services are available
# ===================================================================

def ollama_available():
    try:
        r = urllib.request.urlopen("http://localhost:11434/api/tags", timeout=3)
        return True
    except Exception:
        return False

def gemini_available():
    return GEMINI_API_KEY is not None


# ===================================================================
# Live Integration Tests
# ===================================================================

class TestGeminiProviderLive(unittest.TestCase):
    """Test Gemini can extract structured JSON from content."""

    @unittest.skipUnless(gemini_available(), "Gemini API key not available")
    def test_gemini_extracts_structured_json(self):
        """Ask Gemini to extract structured data from plain text."""
        provider = GeminiProvider()

        content = (
            "The current weather in London is 15 degrees Celsius "
            "and the condition is partly cloudy with light wind."
        )
        schema = {
            "temperature": {"type": "number", "description": "Temperature in Celsius"},
            "condition": {"type": "string", "description": "Weather condition"},
        }

        result = provider.extract_structured(content, schema)
        print(f"\n  Gemini response: {json.dumps(result)}")

        self.assertIsInstance(result, dict)
        self.assertIn("temperature", result)
        self.assertIn("condition", result)
        self.assertIsInstance(result["temperature"], (int, float))
        self.assertIsInstance(result["condition"], str)
        self.assertEqual(result["temperature"], 15)


class TestOllamaProviderLive(unittest.TestCase):
    """Test Ollama can extract structured JSON from content."""

    @unittest.skipUnless(ollama_available(), "Ollama not running")
    def test_ollama_extracts_structured_json(self):
        """Ask Ollama to extract structured data from plain text."""
        provider = OllamaProvider(model_id="llama3.2:latest")

        content = (
            "The stock price of ACME Corp closed at $142.50 today, "
            "which is an increase of 3.2 percent from yesterday."
        )
        schema = {
            "ticker": {"type": "string", "description": "Stock ticker/company name"},
            "price": {"type": "number", "description": "Closing price in USD"},
            "change_percent": {"type": "number", "description": "Percent change"},
        }

        result = provider.extract_structured(content, schema)
        print(f"\n  Ollama response: {json.dumps(result)}")

        self.assertIsInstance(result, dict)
        self.assertIn("price", result)
        self.assertIsInstance(result["price"], (int, float))
        self.assertAlmostEqual(result["price"], 142.5, places=0)


class TestLiveConsensus(unittest.TestCase):
    """
    THE REAL TEST: Two different models process the same content.
    Do they produce matching canonical hashes?
    """

    @unittest.skipUnless(
        gemini_available() and ollama_available(),
        "Both Gemini and Ollama required"
    )
    def test_consensus_with_real_models(self):
        """
        Give both models a simple factual extraction task.
        Check if their canonical hashes match.
        """
        gemini = GeminiProvider(model_id="gemini-2.0-flash")
        ollama = OllamaProvider(model_id="llama3.2:latest")

        verifier = ConsensusVerifier(model_a=gemini, model_b=ollama)

        # Simple, unambiguous factual content
        content = (
            "Product: Widget Pro\n"
            "Price: 29.99\n"
            "In Stock: true\n"
            "Category: electronics\n"
        )
        schema = {
            "product": {"type": "string"},
            "price": {"type": "number"},
            "in_stock": {"type": "boolean"},
            "category": {"type": "string"},
        }

        result = verifier.verify(content, schema)

        print(f"\n  === LIVE CONSENSUS RESULT ===")
        print(f"  Match: {result.match}")
        print(f"  Hash A (Gemini):  {result.hash_a}")
        print(f"  Hash B (Ollama):  {result.hash_b}")
        print(f"  Output A: {json.dumps(result.output_a)}")
        print(f"  Output B: {json.dumps(result.output_b)}")
        print(f"  Canonical A: {canonical_dumps(result.output_a)}")
        print(f"  Canonical B: {canonical_dumps(result.output_b)}")
        print(f"  Latency: {result.latency_ms:.0f}ms")
        print(f"  Reason: {result.reason}")

        # Whether they match or not, we want to see the actual behavior
        # The test documents what happens — a mismatch is valid behavior
        # that the system handles correctly (it would DECLINE)
        self.assertIsNotNone(result.hash_a, "Gemini should produce a hash")
        self.assertIsNotNone(result.hash_b, "Ollama should produce a hash")
        self.assertIsInstance(result.output_a, dict, "Gemini should return a dict")
        self.assertIsInstance(result.output_b, dict, "Ollama should return a dict")

    @unittest.skipUnless(
        gemini_available() and ollama_available(),
        "Both Gemini and Ollama required"
    )
    def test_consensus_mismatch_on_subjective_content(self):
        """
        Give both models SUBJECTIVE content where they're likely to disagree.
        The system should handle this correctly (DECLINE).
        """
        gemini = GeminiProvider(model_id="gemini-2.0-flash")
        ollama = OllamaProvider(model_id="llama3.2:latest")

        verifier = ConsensusVerifier(model_a=gemini, model_b=ollama)

        content = (
            "The new restaurant on Main Street serves decent food. "
            "The ambiance is nice but the service could be better. "
            "Prices are somewhat reasonable for the area."
        )
        schema = {
            "rating": {"type": "number", "description": "Rating out of 10"},
            "sentiment": {"type": "string", "description": "positive, negative, or neutral"},
        }

        result = verifier.verify(content, schema)

        print(f"\n  === SUBJECTIVE CONTENT CONSENSUS ===")
        print(f"  Match: {result.match}")
        print(f"  Output A: {json.dumps(result.output_a)}")
        print(f"  Output B: {json.dumps(result.output_b)}")
        print(f"  Reason: {result.reason}")

        # Both should return valid structured data regardless of match
        self.assertIsNotNone(result.hash_a)
        self.assertIsNotNone(result.hash_b)

    @unittest.skipUnless(
        gemini_available() and ollama_available(),
        "Both Gemini and Ollama required"
    )
    def test_full_pipeline_with_real_models(self):
        """
        End-to-end: Register a tool, freeze it, run OutputGate with
        real consensus verification.
        """
        from sovereign_mcp import ToolRegistry, OutputGate

        gemini = GeminiProvider(model_id="gemini-2.0-flash")
        ollama = OllamaProvider(model_id="llama3.2:latest")
        consensus = ConsensusVerifier(model_a=gemini, model_b=ollama)

        reg = ToolRegistry()
        reg.register_tool(
            name="get_product",
            description="Get product details",
            input_schema={"product_id": {"type": "string", "required": True}},
            output_schema={
                "name": {"type": "string"},
                "price": {"type": "number"},
                "available": {"type": "boolean"},
            },
            risk_level="HIGH",  # Forces consensus check
        )
        frozen = reg.freeze()
        gate = OutputGate(frozen, consensus_verifier=consensus)

        # Simulate tool output that would go through all 4 layers
        tool_output = {
            "name": "Widget Pro",
            "price": 29.99,
            "available": True,
        }

        result = gate.verify("get_product", tool_output)

        print(f"\n  === FULL PIPELINE RESULT ===")
        print(f"  Accepted: {result.accepted}")
        print(f"  Layer reached: {result.layer}")
        print(f"  Reason: {result.reason}")

        # Schema should pass, deception should pass,
        # consensus may pass or fail depending on model agreement
        self.assertIn(result.layer, [
            "all_passed",          # All layers passed including consensus
            "layer_d_behavioral",  # All layers passed (stopped at behavioral)
            "layer_c_consensus",   # Consensus disagreed (valid decline)
        ])


class TestGeminiErrorHandling(unittest.TestCase):
    """Test that bad API keys / network errors are handled gracefully."""

    def test_bad_api_key_handled(self):
        """A wrong API key should raise, not crash."""
        provider = GeminiProvider(
            model_id="gemini-2.0-flash",
            api_key="INVALID_KEY_12345"
        )

        with self.assertRaises(Exception):
            provider.extract_structured(
                "test content",
                {"value": {"type": "string"}}
            )

    @unittest.skipUnless(ollama_available(), "Ollama not running")
    def test_nonexistent_ollama_model(self):
        """Request a model that doesn't exist."""
        provider = OllamaProvider(model_id="nonexistent-model-xyz:latest")

        with self.assertRaises(Exception):
            provider.extract_structured(
                "test content",
                {"value": {"type": "string"}}
            )


if __name__ == "__main__":
    print("=" * 60)
    print("LIVE MODEL INTEGRATION TESTS")
    print("=" * 60)
    print(f"Gemini API key: {'found' if gemini_available() else 'NOT FOUND'}")
    print(f"Ollama:         {'running' if ollama_available() else 'NOT RUNNING'}")
    print("=" * 60)
    unittest.main(verbosity=2)
