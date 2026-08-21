"""
Consensus cache key tests.

The cache keyed on tool name + input parameters only. Layer C verifies the
tool's RESPONSE, so that meant a tool could return clean data once, have the
"consensus matched" verdict cached, and then return anything at all for the
same inputs — skipping Layer C entirely for the whole TTL window (default
300s). That is the compromised-tool scenario Layer C exists to catch.

The output is now part of the key, which keeps the optimisation that matters
(an identical response need not be re-verified) while making any change in the
response a cache miss.
"""

import pytest

from sovereign_mcp import ToolRegistry, OutputGate, ConsensusCache
from sovereign_mcp.consensus import ConsensusVerifier, MockModelProvider


PARAMS = {"ticker": "ACME"}
CLEAN = {"price": 100.0, "note": "ok"}


@pytest.fixture
def gate_parts():
    registry = ToolRegistry()
    registry.register_tool(
        name="get_price",
        description="price",
        input_schema={"ticker": {"type": "string", "required": True}},
        output_schema={"price": {"type": "number"}, "note": {"type": "string"}},
        capabilities=["read_api"],
        risk_level="HIGH",
    )
    frozen = registry.freeze()
    a, b = MockModelProvider("a"), MockModelProvider("b")
    cache = ConsensusCache(default_ttl=300)
    gate = OutputGate(frozen, consensus_verifier=ConsensusVerifier(a, b),
                      consensus_cache=cache)
    return gate, a, b, cache


class TestCacheDoesNotSkipVerificationOnChangedOutput:

    def test_changed_output_is_re_verified(self, gate_parts):
        gate, a, b, _ = gate_parts
        a.set_response(CLEAN)
        b.set_response(CLEAN)
        first = gate.verify("get_price", CLEAN, input_params=PARAMS)
        assert first.accepted is True
        assert "C" in first.layers_passed

        # Same tool, same inputs, DIFFERENT response — and the models now
        # disagree about it. This must not reuse the earlier verdict.
        a.set_response({"price": 1.0})
        b.set_response({"price": 999.0})
        second = gate.verify("get_price", {"price": 100.0, "note": "poisoned"},
                             input_params=PARAMS)
        assert second.accepted is False
        assert second.layer == "layer_c_consensus"

    def test_changed_output_is_a_cache_miss(self, gate_parts):
        gate, a, b, cache = gate_parts
        a.set_response(CLEAN)
        b.set_response(CLEAN)
        gate.verify("get_price", CLEAN, input_params=PARAMS)

        assert cache.get("get_price", PARAMS, CLEAN) is not None
        assert cache.get("get_price", PARAMS, {"price": 100.0, "note": "x"}) is None


class TestCacheStillOptimises:

    def test_identical_output_hits_cache(self, gate_parts):
        gate, a, b, _ = gate_parts
        a.set_response(CLEAN)
        b.set_response(CLEAN)
        gate.verify("get_price", CLEAN, input_params=PARAMS)

        repeat = gate.verify("get_price", CLEAN, input_params=PARAMS)
        assert repeat.accepted is True
        assert "C_cached" in repeat.layers_passed

    def test_key_is_order_insensitive(self):
        cache = ConsensusCache()
        out_a = {"price": 1, "note": "x"}
        out_b = {"note": "x", "price": 1}
        assert (cache._make_key("t", PARAMS, out_a)
                == cache._make_key("t", PARAMS, out_b))

    def test_key_changes_with_output(self):
        cache = ConsensusCache()
        assert (cache._make_key("t", PARAMS, {"price": 1})
                != cache._make_key("t", PARAMS, {"price": 2}))

    def test_key_changes_with_params(self):
        cache = ConsensusCache()
        assert (cache._make_key("t", {"ticker": "A"}, CLEAN)
                != cache._make_key("t", {"ticker": "B"}, CLEAN))

    def test_key_changes_with_tool(self):
        cache = ConsensusCache()
        assert (cache._make_key("t1", PARAMS, CLEAN)
                != cache._make_key("t2", PARAMS, CLEAN))
