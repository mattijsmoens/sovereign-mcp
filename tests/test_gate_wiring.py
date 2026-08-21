"""
OutputGate wiring tests.

Three documented checks existed, were exported, and were never executed:

  * `SchemaValidator.validate_input` — documented as Step 2 of the runtime
    chain — was not called from anywhere in the package. Input types, enums,
    `alpha_only`, lengths and unknown-parameter rejection were all unenforced.
  * `identity_checker` was accepted by the constructor, stored on the
    instance, and never called. Configuring one bought nothing while looking
    like authentication.
  * `input_sanitizer` was likewise stored and never called.

The concrete consequence: `ValueConstraintChecker` skips non-numeric values,
so with no input schema validation a string `"1000000"` passed a frozen
numeric ceiling of 100.
"""

import pytest

from sovereign_mcp import (
    ToolRegistry,
    OutputGate,
    IdentityChecker,
    InputSanitizer,
    ValueConstraintChecker,
)


VALID = {"to": "Alice", "amount": 50}
OUTPUT = {"ok": True}


@pytest.fixture
def frozen():
    registry = ToolRegistry()
    registry.register_tool(
        name="send_money",
        description="send money",
        input_schema={
            "to": {"type": "string", "required": True, "alpha_only": True},
            "amount": {"type": "number", "required": True, "min": 0},
        },
        output_schema={"ok": {"type": "boolean"}},
        capabilities=["write_api"],
        allowed_targets=["/accounts/*"],
        value_constraints={"amount": {"max": 100, "min": 0}},
        risk_level="LOW",
    )
    return registry.freeze()


class TestInputSchemaValidation:

    def test_valid_input_accepted(self, frozen):
        gate = OutputGate(frozen, value_checker=ValueConstraintChecker)
        assert gate.verify("send_money", OUTPUT, input_params=VALID).accepted

    def test_string_number_cannot_bypass_the_ceiling(self, frozen):
        """The bug this closes: ValueConstraintChecker skips non-numerics."""
        gate = OutputGate(frozen, value_checker=ValueConstraintChecker)
        result = gate.verify("send_money", OUTPUT,
                             input_params={"to": "Alice", "amount": "1000000"})
        assert result.accepted is False
        assert result.layer == "input_schema"

    def test_unknown_parameter_rejected(self, frozen):
        gate = OutputGate(frozen)
        result = gate.verify("send_money", OUTPUT,
                             input_params={"to": "Alice", "amount": 50, "evil": 1})
        assert result.accepted is False
        assert result.layer == "input_schema"

    def test_missing_required_parameter_rejected(self, frozen):
        gate = OutputGate(frozen)
        result = gate.verify("send_money", OUTPUT, input_params={"amount": 50})
        assert result.accepted is False
        assert result.layer == "input_schema"

    def test_alpha_only_enforced_on_input(self, frozen):
        gate = OutputGate(frozen)
        result = gate.verify("send_money", OUTPUT,
                             input_params={"to": "Alice; DROP TABLE", "amount": 50})
        assert result.accepted is False
        assert result.layer == "input_schema"

    def test_numeric_ceiling_still_enforced(self, frozen):
        gate = OutputGate(frozen, value_checker=ValueConstraintChecker)
        result = gate.verify("send_money", OUTPUT,
                             input_params={"to": "Alice", "amount": 5000})
        assert result.accepted is False
        assert result.layer == "value_constraints"


class TestIdentityChecker:

    @pytest.fixture
    def checker(self):
        ic = IdentityChecker()
        ic.register_identity("svc", "secret-token", allowed_tools=["send_money"])
        ic.freeze()
        return ic

    def test_missing_identity_fails_closed(self, frozen, checker):
        """A configured checker with no identity must decline, not skip."""
        gate = OutputGate(frozen, identity_checker=checker)
        result = gate.verify("send_money", OUTPUT, input_params=VALID)
        assert result.accepted is False
        assert result.layer == "identity"

    def test_wrong_token_declined(self, frozen, checker):
        gate = OutputGate(frozen, identity_checker=checker)
        result = gate.verify("send_money", OUTPUT, input_params=VALID,
                             identity_id="svc", identity_token="wrong")
        assert result.accepted is False
        assert result.layer == "identity"

    def test_unknown_identity_declined(self, frozen, checker):
        gate = OutputGate(frozen, identity_checker=checker)
        result = gate.verify("send_money", OUTPUT, input_params=VALID,
                             identity_id="nobody", identity_token="x")
        assert result.accepted is False

    def test_correct_identity_accepted(self, frozen, checker):
        gate = OutputGate(frozen, identity_checker=checker)
        result = gate.verify("send_money", OUTPUT, input_params=VALID,
                             identity_id="svc", identity_token="secret-token")
        assert result.accepted is True
        assert "IDENTITY" in result.layers_passed


class TestInputSanitizer:

    def test_traversal_in_params_declined(self, frozen):
        registry = ToolRegistry()
        registry.register_tool(
            name="reader", description="d",
            input_schema={"note": {"type": "string", "required": True}},
            output_schema={"ok": {"type": "boolean"}},
            capabilities=["read_api"], risk_level="LOW",
        )
        gate = OutputGate(registry.freeze(), input_sanitizer=InputSanitizer)
        result = gate.verify("reader", OUTPUT,
                             input_params={"note": "../../etc/passwd"})
        assert result.accepted is False
        assert result.layer == "input_sanitizer"

    def test_clean_params_pass(self, frozen):
        gate = OutputGate(frozen, input_sanitizer=InputSanitizer)
        result = gate.verify("send_money", OUTPUT, input_params=VALID)
        assert result.accepted is True
        assert "SANITIZE" in result.layers_passed


class TestPermissionCheck:

    def test_out_of_scope_target_declined(self, frozen):
        gate = OutputGate(frozen)
        result = gate.verify("send_money", OUTPUT, input_params=VALID,
                             action="write_api", target="/etc/passwd")
        assert result.accepted is False
        assert result.layer == "permissions"

    def test_in_scope_target_accepted(self, frozen):
        gate = OutputGate(frozen)
        result = gate.verify("send_money", OUTPUT, input_params=VALID,
                             action="write_api", target="/accounts/1")
        assert result.accepted is True
        assert "PERM" in result.layers_passed

    def test_not_checked_when_action_target_omitted(self, frozen):
        gate = OutputGate(frozen)
        result = gate.verify("send_money", OUTPUT, input_params=VALID)
        assert result.accepted is True
        assert "PERM" not in result.layers_passed
