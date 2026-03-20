"""
SchemaValidator — Deterministic Input/Output Schema Validation.
===============================================================
Validates tool inputs and outputs against frozen schemas stored in
FrozenNamespace. All checks are deterministic: type matching,
constraint checking, format validation.

This is Layer A of the output verification chain and Step 2/Step 6
of the runtime verification flow.
"""

import re
import math
import logging

logger = logging.getLogger(__name__)


class SchemaValidator:
    """
    Validate data against frozen schemas.

    Supports field-level type checking, required field enforcement,
    constraint validation (min/max, enum, pattern, max_length).

    N-04: Immutable — no attributes can be set or deleted.
    """

    def __setattr__(self, name, value):
        raise AttributeError(
            f"SchemaValidator is immutable. Cannot set '{name}'."
        )

    def __delattr__(self, name):
        raise AttributeError(
            f"SchemaValidator is immutable. Cannot delete '{name}'."
        )

    # Supported type validators
    _TYPE_MAP = {
        "string": str,
        "number": (int, float),
        "integer": int,
        "boolean": bool,
        "array": list,
        "object": dict,
    }

    @classmethod
    def validate_input(cls, params, frozen_schema):
        """
        Validate input parameters against a frozen input schema.

        Args:
            params: Dict of parameter name -> value.
            frozen_schema: Dict defining expected parameters, from FrozenNamespace.

        Returns:
            tuple: (is_valid: bool, reason: str)
        """
        if not isinstance(params, dict):
            return False, "Input must be a dict."

        # Check for required fields
        for field_name, field_def in frozen_schema.items():
            if not isinstance(field_def, dict):
                continue
            if field_def.get("required", False) and field_name not in params:
                return False, f"Missing required field: '{field_name}'"

        # Check each provided parameter
        for field_name, value in params.items():
            if field_name not in frozen_schema:
                return False, f"Unknown parameter: '{field_name}' not in frozen schema."
            field_def = frozen_schema[field_name]
            if not isinstance(field_def, dict):
                continue

            valid, reason = cls._validate_field(field_name, value, field_def)
            if not valid:
                return False, reason

        return True, "Input validation passed."

    @classmethod
    def validate_output(cls, output, frozen_schema):
        """
        Validate tool output against a frozen output schema.

        This is Layer A of the output verification chain.

        Args:
            output: Dict of output data from tool execution.
            frozen_schema: Dict defining expected output format.

        Returns:
            tuple: (is_valid: bool, reason: str)
        """
        if not isinstance(output, dict):
            return False, "Output must be a dict."

        # Check all schema-defined fields exist in output
        for field_name, field_def in frozen_schema.items():
            if not isinstance(field_def, dict):
                continue
            required = field_def.get("required", True)  # Output fields default required
            if required and field_name not in output:
                return False, f"Missing required output field: '{field_name}'"

        # Validate each output field
        for field_name, value in output.items():
            if field_name not in frozen_schema:
                return False, f"Unexpected output field: '{field_name}' not in frozen schema."
            field_def = frozen_schema[field_name]
            if not isinstance(field_def, dict):
                continue

            valid, reason = cls._validate_field(field_name, value, field_def)
            if not valid:
                return False, reason

        return True, "Output schema validation passed."

    @classmethod
    def _validate_field(cls, name, value, field_def):
        """
        Validate a single field value against its schema definition.

        Checks: type, min, max, min_length, max_length, enum, pattern,
                alpha_only, items (for arrays).

        Returns:
            tuple: (is_valid: bool, reason: str)
        """
        # Null check (must come BEFORE type check)
        if value is None:
            if field_def.get("required", False):
                return False, f"Field '{name}' is required but got null."
            return True, "OK"

        # Type check
        expected_type = field_def.get("type")
        if expected_type:
            python_type = cls._TYPE_MAP.get(expected_type)
            if python_type:
                # Special case: bool is subclass of int in Python,
                # but a boolean should NOT pass an integer/number check.
                if isinstance(value, bool) and expected_type in ("integer", "number"):
                    return False, (
                        f"Type mismatch for '{name}': expected {expected_type}, "
                        f"got bool"
                    )
                if not isinstance(value, python_type):
                    return False, (
                        f"Type mismatch for '{name}': expected {expected_type}, "
                        f"got {type(value).__name__}"
                    )

        # Numeric constraints (exclude booleans — bool is subclass of int)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            # Reject NaN and Infinity — NaN comparisons always return False
            if math.isnan(value) or math.isinf(value):
                return False, f"Field '{name}': value {value} is not a valid finite number"
            min_val = field_def.get("min")
            max_val = field_def.get("max")
            if min_val is not None and value < min_val:
                return False, f"Field '{name}': value {value} below minimum {min_val}"
            if max_val is not None and value > max_val:
                return False, f"Field '{name}': value {value} above maximum {max_val}"

        # String constraints
        if isinstance(value, str):
            min_length = field_def.get("min_length")
            max_length = field_def.get("max_length")
            if min_length is not None and len(value) < min_length:
                return False, f"Field '{name}': length {len(value)} below minimum {min_length}"
            if max_length is not None and len(value) > max_length:
                return False, f"Field '{name}': length {len(value)} above maximum {max_length}"

            # Alpha only constraint
            if field_def.get("alpha_only") and not re.match(r'^[a-zA-Z\s]+$', value):
                return False, f"Field '{name}': must contain only alphabetic characters."

            # Pattern constraint (with ReDoS protection via timeout)
            pattern = field_def.get("pattern")
            if pattern:
                try:
                    import threading
                    match_result = [None]
                    def _run_match():
                        match_result[0] = re.match(pattern, value)
                    t = threading.Thread(target=_run_match, daemon=True)
                    t.start()
                    t.join(timeout=2.0)  # 2-second timeout
                    if t.is_alive():
                        logger.warning(
                            f"[SchemaValidator] Pattern timeout for field '{name}' "
                            f"— possible ReDoS. Pattern blocked."
                        )
                        return False, f"Field '{name}': pattern validation timed out (possible ReDoS)."
                    if not match_result[0]:
                        return False, f"Field '{name}': does not match required pattern."
                except re.error as e:
                    return False, f"Field '{name}': invalid pattern: {e}"

        # Enum constraint
        allowed_values = field_def.get("enum")
        if allowed_values is not None:
            if value not in allowed_values:
                return False, (
                    f"Field '{name}': value '{value}' not in allowed values: "
                    f"{allowed_values}"
                )

        # Array constraints
        if isinstance(value, list):
            max_items = field_def.get("max_items")
            if max_items is not None and len(value) > max_items:
                return False, (
                    f"Field '{name}': array length {len(value)} exceeds "
                    f"maximum {max_items}"
                )
            # Validate items if item schema defined
            item_schema = field_def.get("items")
            if item_schema:
                for i, item in enumerate(value):
                    valid, reason = cls._validate_field(
                        f"{name}[{i}]", item, item_schema
                    )
                    if not valid:
                        return False, reason

        return True, "OK"
