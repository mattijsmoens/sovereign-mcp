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

import hmac
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

class OpenRouterMCPProvider(ModelProvider):
    """Native OpenRouter provider for Sovereign-MCP Consensus."""
    
    def __init__(self, model_id, api_key, enforce_grammar=False):
        super().__init__(model_id, temperature=0)
        self.api_key = api_key
        self.enforce_grammar = enforce_grammar

    def extract_structured(self, content, schema, system_prompt=None):
        # Imported lazily so the core package stays stdlib-only. Only the
        # HTTP-backed providers need `requests`.
        import requests

        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        if not system_prompt:
            prompt = f"Return ONLY valid JSON matching this schema:\n{json.dumps(schema, indent=2)}\n\nData:\n{content}"
        else:
            prompt = f"{system_prompt}\n\nData:\n{content}\n\nReturn ONLY valid JSON matching this schema:\n{json.dumps(schema, indent=2)}"
        
        payload = {
            "model": self.model_id,
            "temperature": 0,
            "messages": [{"role": "user", "content": prompt}]
        }
        
        if self.enforce_grammar:
            # OpenRouter / OpenAI strict structured outputs
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "extraction",
                    "strict": True,
                    "schema": schema
                }
            }
        else:
            payload["response_format"] = {"type": "json_object"}
        
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        if response.status_code != 200:
            raise RuntimeError(f"OpenRouter Error: {response.text}")
            
        data = response.json()
        raw_output = data["choices"][0]["message"]["content"]
        
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError:
            raw_output = raw_output.replace("```json", "").replace("```", "").strip()
            return json.loads(raw_output)

class LocalMCPProvider(ModelProvider):
    """Native Local (Ollama/LM Studio) provider for Air-Gapped Sovereign-MCP Consensus."""
    
    def __init__(self, model_id, base_url="http://localhost:11434/v1", enforce_grammar=False):
        super().__init__(model_id, temperature=0)
        self.base_url = base_url
        self.enforce_grammar = enforce_grammar

    def extract_structured(self, content, schema, system_prompt=None):
        # Imported lazily so the core package stays stdlib-only.
        import requests

        url = f"{self.base_url}/chat/completions"
        headers = {"Content-Type": "application/json"}
        
        if not system_prompt:
            prompt = f"Return ONLY valid JSON matching this schema:\n{json.dumps(schema, indent=2)}\n\nData:\n{content}"
        else:
            prompt = f"{system_prompt}\n\nData:\n{content}\n\nReturn ONLY valid JSON matching this schema:\n{json.dumps(schema, indent=2)}"
        
        payload = {
            "model": self.model_id,
            "temperature": 0,
            "messages": [{"role": "user", "content": prompt}]
        }
        
        if self.enforce_grammar:
            # Ollama native strict structured outputs (passes schema as format)
            payload["format"] = schema
        else:
            payload["response_format"] = {"type": "json_object"}
        
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        if response.status_code != 200:
            raise RuntimeError(f"Local LLM Error: {response.text}")
            
        data = response.json()
        raw_output = data["choices"][0]["message"]["content"]
        
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError:
            raw_output = raw_output.replace("```json", "").replace("```", "").strip()
            return json.loads(raw_output)

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

    def __init__(self, model_a, model_b=None, consensus_models=None):
        """
        Args:
            model_a: Primary model provider (ModelProvider subclass).
            model_b: Verifier model provider (ModelProvider subclass).
            consensus_models: List of additional ModelProvider subclasses for N-model consensus.

        Raises:
            ValueError: If models are not diverse, or if temperature != 0.
        """
        self.models = [model_a]
        if model_b:
            self.models.append(model_b)
        if consensus_models:
            self.models.extend(consensus_models)
            
        if len(self.models) < 2:
            raise ValueError("Consensus requires at least two models.")

        model_ids = [m.model_id for m in self.models]
        if len(model_ids) != len(set(model_ids)):
            raise ValueError(
                "CONSENSUS INTEGRITY VIOLATION: All models must use "
                f"different models. Provided are '{model_ids}'. "
                "Same model = same output = tautology (comparing X to X)."
            )
            
        for m in self.models:
            if m.temperature != 0:
                raise ValueError(
                    "CONSENSUS INTEGRITY VIOLATION: All models must use temperature=0. "
                    f"Model {m.model_id} has temperature={m.temperature}. "
                    "Temperature > 0 causes random output = false rejections."
                )

        self._model_a = self.models[0]
        self._model_b = self.models[1]

        logger.info(
            f"[Consensus] Initialized. Models: {model_ids}"
        )

    def verify(self, tool_output, frozen_schema, verification_source=None):
        """
        Run dual-model consensus verification.

        Args:
            tool_output: Raw output from the MCP tool.
            frozen_schema: Frozen output schema from registry.
            verification_source: Optional independent data source for the
                verifier models (Countermeasure 2). If None, every model reads
                the same tool_output. Accepts either:

                  * a CALLABLE - invoked with no arguments; its return value is
                    the independent data the verifier models read. This is the
                    form that actually delivers the countermeasure, because the
                    verifiers see data retrieved separately from the tool.

                  * any other value (typically a URL string) - passed to the
                    provider verbatim. NOTE: nothing here fetches it. The
                    provider is then responsible for retrieval, and if it does
                    not perform any, the verifier models receive the URL itself
                    as their content rather than independent data - which does
                    not defeat a poisoned source. Prefer the callable form.

        Returns:
            ConsensusResult with match status, hashes, timing, and model outputs.
        """
        import concurrent.futures
        start_time = time.time()

        resolved_source = verification_source
        if callable(verification_source):
            try:
                resolved_source = verification_source()
            except Exception as e:
                # Fail closed: an independent source that cannot be reached is
                # not grounds to silently fall back to the tool's own output,
                # which is exactly the data being cross-checked.
                elapsed = (time.time() - start_time) * 1000
                return ConsensusResult(
                    match=False,
                    reason=f"Verification source unavailable: {e}",
                    latency_ms=elapsed,
                    used_independent_source=True,
                )

        inputs = [tool_output]
        for _ in range(1, len(self.models)):
            inputs.append(resolved_source if resolved_source is not None else tool_output)

        def fetch(idx, model, inp):
            try:
                out = model.extract_structured(inp, frozen_schema)
                return out, None
            except Exception as e:
                return None, f"Model {idx+1} ({model.model_id}) error: {e}"

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.models)) as executor:
            futures = [
                executor.submit(fetch, i, m, inp)
                for i, (m, inp) in enumerate(zip(self.models, inputs))
            ]
            results = [f.result() for f in futures]

        outputs = []
        hashes = []
        
        for i, (out, err) in enumerate(results):
            if err:
                elapsed = (time.time() - start_time) * 1000
                return ConsensusResult(
                    match=False,
                    reason=err,
                    latency_ms=elapsed,
                    used_independent_source=verification_source is not None,
                    outputs=[r[0] for r in results[:i+1]],
                    hashes=[canonical_hash(r[0]) if r[0] else None for r in results[:i+1]]
                )
            outputs.append(out)
            hashes.append(canonical_hash(out))

        # Deterministic comparison: canonical hash match
        base_hash = hashes[0]
        # Constant-time comparison to prevent timing attacks.
        # all() with a generator would short-circuit, so evaluate every
        # comparison before reducing.
        match = all([hmac.compare_digest(base_hash, h) for h in hashes[1:]])
        elapsed = (time.time() - start_time) * 1000

        if match:
            logger.info(
                f"[Consensus] MATCH. Hash: {base_hash[:16]}... "
                f"Latency: {elapsed:.1f}ms"
            )
            reason = "Consensus: hashes match."
        else:
            logger.warning(
                f"[Consensus] MISMATCH. "
                f"Hashes: {[h[:16] + '...' for h in hashes]} "
                f"Latency: {elapsed:.1f}ms"
            )
            reason = (
                f"Consensus MISMATCH: Models produced different data. "
                f"Hashes: {[h[:8] for h in hashes]}"
            )

        return ConsensusResult(
            match=match,
            reason=reason,
            latency_ms=elapsed,
            used_independent_source=verification_source is not None,
            hashes=hashes,
            outputs=outputs
        )


class ConsensusResult:
    """Result of a consensus verification. Immutable after creation."""
    __slots__ = ('match', 'hash_a', 'hash_b', 'output_a', 'output_b',
                 'hashes', 'outputs',
                 'reason', 'latency_ms', 'used_independent_source', '_initialized')

    def __init__(self, match, hash_a=None, hash_b=None, output_a=None, output_b=None,
                 reason="", latency_ms=0, used_independent_source=False,
                 hashes=None, outputs=None):
        object.__setattr__(self, 'match', match)
        
        if hashes is None:
            hashes = [hash_a, hash_b] if hash_b else ([hash_a] if hash_a else [])
        if outputs is None:
            outputs = [output_a, output_b] if output_b else ([output_a] if output_a else [])
            
        object.__setattr__(self, 'hashes', hashes)
        object.__setattr__(self, 'outputs', outputs)
        
        object.__setattr__(self, 'hash_a', hashes[0] if hashes else hash_a)
        object.__setattr__(self, 'hash_b', hashes[1] if len(hashes) > 1 else hash_b)
        object.__setattr__(self, 'output_a', outputs[0] if outputs else output_a)
        object.__setattr__(self, 'output_b', outputs[1] if len(outputs) > 1 else output_b)
        
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
            "hashes": self.hashes,
            "reason": self.reason,
            "latency_ms": round(self.latency_ms, 1),
            "used_independent_source": self.used_independent_source,
        }

    def __repr__(self):
        status = "MATCH" if self.match else "MISMATCH"
        return f"ConsensusResult({status}, {self.latency_ms:.1f}ms)"
