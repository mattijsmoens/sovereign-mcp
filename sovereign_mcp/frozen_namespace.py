"""
FrozenNamespace — Immutable Metaclass for Security-Critical Data.
=================================================================
Provides a Python metaclass that prevents modification of class attributes
after class creation. This is the architectural root of trust for the
entire MCP Security Architecture.

Extracted from SovereignShield CoreSafety and extended for MCP tool
definition freezing.

Security Properties:
    - Class attributes cannot be modified via __setattr__
    - Class attributes cannot be deleted via __delattr__
    - Instance creation is blocked (class-level only)
    - The constraint is enforced by the Python runtime, not by policy

Patent: Sovereign Shield Patent 3 (Immutable Runtime Constraints)
         Sovereign Shield Patent 18 (Deterministic Validation)
         Sovereign Shield Patent 20 (MCP Security Architecture)
"""

import hashlib
import json
import copy
import logging

logger = logging.getLogger(__name__)


class FrozenNamespace(type):
    """
    Metaclass that prevents modification of class attributes at runtime.

    Any attempt to set, modify, or delete a class attribute on a class
    using this metaclass will raise a TypeError. This ensures that security
    constants defined at class creation time remain immutable throughout
    the lifetime of the process.

    Exception: attributes starting with '_mutable_' can be modified.
    This is used for internal state that must change (e.g., hash seals
    that are set once during initialization).

    SECURITY: __getattribute__ returns deep copies of mutable containers
    (dict, list) to prevent external mutation of frozen data via reference.
    """

    # L-01: Cache deep copies to avoid O(n) copy on every access.
    # Since FrozenNamespace is immutable, cached copies are always valid.
    # We use a separate dict (not on the class itself) to avoid triggering __setattr__.
    _deep_copy_cache = {}

    def __getattribute__(cls, key):
        value = super().__getattribute__(key)
        # Deep-copy mutable containers to prevent reference mutation attacks.
        # Cache the copy since the source data never changes (immutable class).
        if isinstance(value, (dict, list)):
            cache_key = (id(cls), key)
            cached = FrozenNamespace._deep_copy_cache.get(cache_key)
            if cached is not None:
                # Return a fresh copy of the cached structure (not the cache ref itself)
                return copy.deepcopy(cached)
            fresh_copy = copy.deepcopy(value)
            FrozenNamespace._deep_copy_cache[cache_key] = fresh_copy
            return copy.deepcopy(fresh_copy)
        return value

    def __setattr__(cls, key, value):
        # Allow one-time writes to mutable slots (e.g., _mutable_hash)
        if key.startswith("_mutable_"):
            # Allow only if current value is None (one-time set)
            current = cls.__dict__.get(key)
            if current is None:
                super().__setattr__(key, value)
                return
            raise TypeError(
                f"IMMUTABILITY VIOLATION: Mutable slot '{key}' already set. "
                f"Cannot overwrite."
            )
        raise TypeError(
            f"IMMUTABILITY VIOLATION: Cannot modify protected attribute '{key}' "
            f"on {cls.__name__}"
        )

    def __delattr__(cls, key):
        raise TypeError(
            f"IMMUTABILITY VIOLATION: Cannot delete protected attribute '{key}' "
            f"on {cls.__name__}"
        )

    def __call__(cls, *args, **kwargs):
        raise TypeError(
            f"IMMUTABILITY VIOLATION: Cannot instantiate {cls.__name__}. "
            f"FrozenNamespace classes are used at the class level only."
        )


def freeze_tool_definition(name, description, input_schema, output_schema,
                           capabilities=None, allowed_targets=None,
                           risk_level="HIGH", verification_source=None,
                           value_constraints=None, approval_thresholds=None):
    """
    Create a frozen tool definition as a FrozenNamespace class.

    All fields are deep-copied and frozen. The SHA-256 hash is computed
    over the canonical JSON representation of all fields.

    Args:
        name: Tool name (string identifier).
        description: Tool description (what it does).
        input_schema: Dict defining input parameters, types, constraints.
        output_schema: Dict defining expected output format.
        capabilities: List of declared capabilities (e.g., ["read_file"]).
        allowed_targets: List of allowed target resources.
        risk_level: "LOW", "MEDIUM", or "HIGH" (default: "HIGH").
        verification_source: Independent verification source for Model B.
        value_constraints: Dict of frozen numeric limits per action parameter.
        approval_thresholds: Dict of human-in-the-loop thresholds.

    Returns:
        A FrozenNamespace class with all fields frozen and hash-sealed.

    Raises:
        ValueError: If required fields are missing or invalid.
    """
    if not name or not isinstance(name, str):
        raise ValueError("Tool name must be a non-empty string.")
    if not input_schema or not isinstance(input_schema, dict):
        raise ValueError("Input schema must be a non-empty dict.")
    if not output_schema or not isinstance(output_schema, dict):
        raise ValueError("Output schema must be a non-empty dict.")
    if risk_level not in ("LOW", "MEDIUM", "HIGH"):
        raise ValueError(f"Risk level must be LOW, MEDIUM, or HIGH. Got: {risk_level}")

    # Deep copy all mutable inputs to prevent reference sharing
    frozen_input_schema = copy.deepcopy(input_schema)
    frozen_output_schema = copy.deepcopy(output_schema)
    frozen_capabilities = tuple(capabilities) if capabilities else ()
    frozen_targets = tuple(allowed_targets) if allowed_targets else ()
    frozen_value_constraints = copy.deepcopy(value_constraints) if value_constraints else {}
    frozen_approval_thresholds = copy.deepcopy(approval_thresholds) if approval_thresholds else {}

    # Compute SHA-256 hash over canonical representation
    canonical_data = {
        "name": name,
        "description": description,
        "input_schema": frozen_input_schema,
        "output_schema": frozen_output_schema,
        "capabilities": list(frozen_capabilities),
        "allowed_targets": list(frozen_targets),
        "risk_level": risk_level,
        "verification_source": verification_source,
        "value_constraints": frozen_value_constraints,
        "approval_thresholds": frozen_approval_thresholds,
    }
    canonical_json = json.dumps(canonical_data, sort_keys=True, separators=(",", ":"))
    definition_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    # Create the frozen class dynamically
    attrs = {
        "TOOL_NAME": name,
        "DESCRIPTION": description,
        "INPUT_SCHEMA": frozen_input_schema,
        "OUTPUT_SCHEMA": frozen_output_schema,
        "CAPABILITIES": frozen_capabilities,
        "ALLOWED_TARGETS": frozen_targets,
        "RISK_LEVEL": risk_level,
        "VERIFICATION_SOURCE": verification_source,
        "VALUE_CONSTRAINTS": frozen_value_constraints,
        "APPROVAL_THRESHOLDS": frozen_approval_thresholds,
        "DEFINITION_HASH": definition_hash,
        "CANONICAL_JSON": canonical_json,
    }

    frozen_class = FrozenNamespace(f"FrozenTool_{name}", (), attrs)

    logger.info(
        f"[FrozenNamespace] Tool '{name}' frozen. "
        f"Hash: {definition_hash[:16]}... Risk: {risk_level}"
    )

    return frozen_class


def compute_hash(data):
    """
    Compute SHA-256 hash of arbitrary data.

    Args:
        data: String or bytes to hash.

    Returns:
        Hex digest string.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()
