"""
Consensus — Dual-Model Structured JSON Consensus Verification.
===============================================================
Layer C of the output verification chain. Two independent models
process tool output (or independent sources) and produce structured JSON.
The DECISION is a deterministic SHA-256 hash comparison.

The models are probabilistic. The decision mechanism is deterministic.

Consensus Integrity Requirements (from architecture doc):
    1. Model Diversity: Model A and B MUST use different model weights
    2. Deterministic Inference: Both at temperature = 0
    3. Schema Tightness: Frozen schema must be as specific as possible
"""

import json
import time
import logging
from sovereign_mcp.canonical_json import canonical_hash, hashes_match, canonical_dumps

logger = logging.getLogger(__name__)


class ModelProvider:
    """
    Abstract base for LLM model providers.

    Implement this for each model backend (OpenAI, Gemini, Ollama, etc.)
    model_id and temperature are read-only after init.
    """

    def __init__(self, model_id, temperature=0):
        """
        Args:
            model_id: Identifier for the model (e.g., "gpt-4", "claude-3").
            temperature: Must be 0 for consensus (frozen at registration).

        Raises:
            ValueError: If temperature is not 0.
        """
        if temperature != 0:
            raise ValueError(
                f"ModelProvider requires temperature=0 for deterministic consensus. "
                f"Got temperature={temperature} for model '{model_id}'."
            )
        self.__model_id = model_id
        self.__temperature = temperature

    @property
    def model_id(self):
        return self.__model_id

    @property
    def temperature(self):
        return self.__temperature

    def extract_structured(self, content, schema):
        """
        Extract structured JSON from content according to schema.

        Args:
            content: Raw content to process (tool output or verification source).
            schema: Frozen output schema dict defining fields, types, constraints.

        Returns:
            dict: Structured JSON matching the schema.

        Raises:
            NotImplementedError: Subclasses must implement.
        """
        raise NotImplementedError("Subclasses must implement extract_structured()")


class MockModelProvider(ModelProvider):
    """
    Mock provider for testing. Returns a fixed response.
    """

    def __init__(self, model_id="mock", response=None):
        super().__init__(model_id, temperature=0)
        self._response = response or {}

    def set_response(self, response):
        """Set the response this mock will return."""
        self._response = response

    def extract_structured(self, content, schema):
        return self._response


class ConsensusVerifier:
    """
    Dual-model structured JSON consensus verification.

    Both models extract structured data from tool output (or independent
    sources). Both outputs are canonical-normalized and hashed.
    Hash match = accept. Hash mismatch = decline. Deterministic.

    Usage:
        verifier = ConsensusVerifier(
            model_a=OpenAIProvider("gpt-4"),
            model_b=OllamaProvider("llama3"),
        )
        result = verifier.verify(tool_output, frozen_schema)
    """

    def __init__(self, model_a, model_b):
        """
        Args:
            model_a: Primary model provider (ModelProvider subclass).
            model_b: Verifier model provider (ModelProvider subclass).

        Raises:
            ValueError: If both models use the same model_id (tautology).
        """
        if model_a.model_id == model_b.model_id:
            raise ValueError(
                "CONSENSUS INTEGRITY VIOLATION: Model A and Model B must use "
                f"different models. Both are '{model_a.model_id}'. "
                "Same model = same output = tautology (comparing X to X)."
            )
        if model_a.temperature != 0 or model_b.temperature != 0:
            raise ValueError(
                "CONSENSUS INTEGRITY VIOLATION: Both models must use temperature=0. "
                f"Model A: {model_a.temperature}, Model B: {model_b.temperature}. "
                "Temperature > 0 causes random output = false rejections."
            )

        self._model_a = model_a
        self._model_b = model_b

        logger.info(
            f"[Consensus] Initialized. Model A: {model_a.model_id}, "
            f"Model B: {model_b.model_id}"
        )

    def verify(self, tool_output, frozen_schema, verification_source=None):
        """
        Run dual-model consensus verification.

        Args:
            tool_output: Raw output from the MCP tool.
            frozen_schema: Frozen output schema from registry.
            verification_source: Optional independent data source for Model B
                                 (Countermeasure 2: independent source verification).
                                 If None, Model B uses the same tool_output.

        Returns:
            ConsensusResult with match status, hashes, timing, and model outputs.
        """
        start_time = time.time()

        # Model A processes tool output
        try:
            output_a = self._model_a.extract_structured(tool_output, frozen_schema)
        except Exception as e:
            elapsed = (time.time() - start_time) * 1000
            return ConsensusResult(
                match=False,
                hash_a=None,
                hash_b=None,
                output_a=None,
                output_b=None,
                reason=f"Model A ({self._model_a.model_id}) error: {e}",
                latency_ms=elapsed,
            )

        # Model B processes either same output or independent source
        model_b_input = verification_source if verification_source is not None else tool_output
        try:
            output_b = self._model_b.extract_structured(model_b_input, frozen_schema)
        except Exception as e:
            elapsed = (time.time() - start_time) * 1000
            return ConsensusResult(
                match=False,
                hash_a=canonical_hash(output_a) if output_a else None,
                hash_b=None,
                output_a=output_a,
                output_b=None,
                reason=f"Model B ({self._model_b.model_id}) error: {e}",
                latency_ms=elapsed,
            )

        # Deterministic comparison: canonical hash match
        match, hash_a, hash_b = hashes_match(output_a, output_b)
        elapsed = (time.time() - start_time) * 1000

        if match:
            logger.info(
                f"[Consensus] MATCH. Hash: {hash_a[:16]}... "
                f"Latency: {elapsed:.1f}ms"
            )
            reason = "Consensus: hashes match."
        else:
            logger.warning(
                f"[Consensus] MISMATCH. "
                f"Hash A: {hash_a[:16]}... Hash B: {hash_b[:16]}... "
                f"Latency: {elapsed:.1f}ms"
            )
            reason = (
                f"Consensus MISMATCH: Model A ({self._model_a.model_id}) "
                f"and Model B ({self._model_b.model_id}) produced different data."
            )

        return ConsensusResult(
            match=match,
            hash_a=hash_a,
            hash_b=hash_b,
            output_a=output_a,
            output_b=output_b,
            reason=reason,
            latency_ms=elapsed,
            used_independent_source=verification_source is not None,
        )


class ConsensusResult:
    """Result of a consensus verification. Immutable after creation."""
    __slots__ = ('match', 'hash_a', 'hash_b', 'output_a', 'output_b',
                 'reason', 'latency_ms', 'used_independent_source', '_initialized')

    def __init__(self, match, hash_a, hash_b, output_a, output_b,
                 reason, latency_ms, used_independent_source=False):
        object.__setattr__(self, 'match', match)
        object.__setattr__(self, 'hash_a', hash_a)
        object.__setattr__(self, 'hash_b', hash_b)
        object.__setattr__(self, 'output_a', output_a)
        object.__setattr__(self, 'output_b', output_b)
        object.__setattr__(self, 'reason', reason)
        object.__setattr__(self, 'latency_ms', latency_ms)
        object.__setattr__(self, 'used_independent_source', used_independent_source)
        object.__setattr__(self, '_initialized', True)

    def __setattr__(self, name, value):
        if getattr(self, '_initialized', False):
            raise AttributeError(
                f"ConsensusResult is immutable. Cannot set '{name}'."
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name):
        raise AttributeError(
            f"ConsensusResult is immutable. Cannot delete '{name}'."
        )

    def to_dict(self):
        return {
            "match": self.match,
            "hash_a": self.hash_a,
            "hash_b": self.hash_b,
            "reason": self.reason,
            "latency_ms": round(self.latency_ms, 1),
            "used_independent_source": self.used_independent_source,
        }

    def __repr__(self):
        status = "MATCH" if self.match else "MISMATCH"
        return f"ConsensusResult({status}, {self.latency_ms:.1f}ms)"
