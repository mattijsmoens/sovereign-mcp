"""
ValueConstraintChecker — Frozen Numeric Limits (Countermeasure 1).
==================================================================
Hard numeric limits per action parameter, frozen in FrozenNamespace.
Deterministic number comparison. No model judgment. No AI.

The agent cannot raise its own limit at runtime. Even if both models
agree the amount is correct, the hard ceiling blocks it.
"""

import math
import logging

logger = logging.getLogger(__name__)


class ValueConstraintChecker:
    """
    Check input parameters against frozen value constraints.

    Constraints are defined per tool at registration and frozen.
    Each constraint specifies a parameter name and limits:
        - max: maximum allowed value
        - min: minimum allowed value
    """

    @classmethod
    def check(cls, params, constraints):
        """
        Check all input parameters against frozen constraints.

        Args:
            params: Dict of parameter name -> value.
            constraints: Dict of parameter name -> constraint dict.
                         From FrozenNamespace (frozen at registration).

        Returns:
            tuple: (passes: bool, reason: str)
        """
        if not constraints:
            return True, "No value constraints defined."

        for param_name, constraint in constraints.items():
            if param_name not in params:
                logger.warning(
                    f"[ValueConstraint] Constrained parameter '{param_name}' "
                    f"not present in input — skipping check."
                )
                continue  # Parameter not provided, skip

            value = params[param_name]
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                continue  # Only check numeric values (exclude booleans)

            # Reject NaN and Infinity — NaN comparisons always return False
            # in Python, so NaN would silently bypass all min/max checks.
            if math.isnan(value) or math.isinf(value):
                logger.warning(
                    f"[ValueConstraint] DECLINED: {param_name}={value} "
                    f"is not a valid finite number"
                )
                return False, (
                    f"Value constraint violated: '{param_name}' = {value} "
                    f"is not a valid finite number."
                )

            # Max constraint (L-19: validate constraint value type)
            max_val = constraint.get("max")
            if max_val is not None:
                if not isinstance(max_val, (int, float)) or isinstance(max_val, bool):
                    logger.error(
                        f"[ValueConstraint] INVALID CONSTRAINT: max for '{param_name}' "
                        f"is {type(max_val).__name__}, not numeric. Blocking (fail-safe)."
                    )
                    return False, f"Invalid constraint: 'max' for '{param_name}' is not numeric."
                if value > max_val:
                    logger.warning(
                        f"[ValueConstraint] DECLINED: {param_name}={value} "
                        f"exceeds frozen max={max_val}"
                    )
                    return False, (
                        f"Value constraint violated: '{param_name}' = {value} "
                        f"exceeds frozen maximum of {max_val}."
                    )

            # Min constraint (L-19: validate constraint value type)
            min_val = constraint.get("min")
            if min_val is not None:
                if not isinstance(min_val, (int, float)) or isinstance(min_val, bool):
                    logger.error(
                        f"[ValueConstraint] INVALID CONSTRAINT: min for '{param_name}' "
                        f"is {type(min_val).__name__}, not numeric. Blocking (fail-safe)."
                    )
                    return False, f"Invalid constraint: 'min' for '{param_name}' is not numeric."
                if value < min_val:
                    logger.warning(
                        f"[ValueConstraint] DECLINED: {param_name}={value} "
                        f"below frozen min={min_val}"
                    )
                    return False, (
                        f"Value constraint violated: '{param_name}' = {value} "
                        f"below frozen minimum of {min_val}."
                    )

        return True, "All value constraints passed."
