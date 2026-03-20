"""
ToolRegistry — MCP Tool Definition Manager.
============================================
Manages the lifecycle of MCP tool definitions:
    1. Registration (staging area, mutable)
    2. Freezing (locks everything into FrozenNamespace, computes hashes)
    3. Runtime verification (hash checks against frozen references)

After freeze(), no more tools can be registered. The registry itself
becomes immutable. This is Phase 1 of the architecture.
"""

import hashlib
import hmac
import json
import logging
from sovereign_mcp.frozen_namespace import freeze_tool_definition, compute_hash

logger = logging.getLogger(__name__)


class ToolRegistry:
    """
    MCP Tool Definition Registry with freeze-seal lifecycle.

    Usage:
        registry = ToolRegistry()
        registry.register_tool(
            name="get_weather",
            description="Fetch current weather for a city",
            input_schema={"city": {"type": "string", "required": True}},
            output_schema={"temperature": {"type": "number"}, "condition": {"type": "string"}},
            capabilities=["read_api"],
            risk_level="LOW",
        )
        frozen = registry.freeze()

        # After freeze:
        tool = frozen.get_tool("get_weather")
        is_valid = frozen.verify_integrity("get_weather")
    """

    def __init__(self):
        self._staging = {}      # name -> dict of tool definition kwargs
        self._frozen = False
        self._frozen_tools = {} # name -> FrozenNamespace class (after freeze)
        self._aggregate_hash = None
        logger.info("[ToolRegistry] Initialized. Ready for tool registration.")

    @property
    def is_frozen(self):
        """Whether the registry has been frozen."""
        return self._frozen

    def register_tool(self, name, description, input_schema, output_schema,
                      capabilities=None, allowed_targets=None,
                      risk_level="HIGH", verification_source=None,
                      value_constraints=None, approval_thresholds=None):
        """
        Register a tool definition in the staging area.

        Args:
            name: Unique tool identifier.
            description: What the tool does.
            input_schema: Dict defining parameters, types, constraints.
            output_schema: Dict defining expected output format.
            capabilities: List of declared capabilities.
            allowed_targets: List of allowed resource targets.
            risk_level: "LOW", "MEDIUM", or "HIGH".
            verification_source: Independent data source for Model B.
            value_constraints: Frozen numeric limits per parameter.
            approval_thresholds: Human-in-the-loop thresholds.

        Raises:
            RuntimeError: If registry is already frozen.
            ValueError: If tool name already registered.
        """
        if self._frozen:
            raise RuntimeError(
                f"REGISTRY SEALED: Cannot register tool '{name}' after freeze. "
                f"Use dynamic tool registration process (sandbox staging + "
                f"controlled freeze cycle) for runtime additions."
            )
        if name in self._staging:
            raise ValueError(f"Tool '{name}' is already registered.")

        self._staging[name] = {
            "name": name,
            "description": description,
            "input_schema": input_schema,
            "output_schema": output_schema,
            "capabilities": capabilities,
            "allowed_targets": allowed_targets,
            "risk_level": risk_level,
            "verification_source": verification_source,
            "value_constraints": value_constraints,
            "approval_thresholds": approval_thresholds,
        }
        logger.info(f"[ToolRegistry] Tool '{name}' staged for registration.")

    def freeze(self):
        """
        Freeze all staged tool definitions.

        Creates FrozenNamespace classes for each tool, computes SHA-256
        hashes, and seals the registry. After this call, no modifications
        are possible.

        Returns:
            FrozenRegistry: An immutable registry of all frozen tools.

        Raises:
            RuntimeError: If already frozen or no tools registered.
        """
        if self._frozen:
            raise RuntimeError("Registry is already frozen.")
        if not self._staging:
            raise RuntimeError("No tools registered. Register at least one tool before freezing.")

        # Freeze each tool definition
        for name, kwargs in self._staging.items():
            frozen_tool = freeze_tool_definition(**kwargs)
            self._frozen_tools[name] = frozen_tool

        # Compute aggregate hash over all individual hashes (sorted by name)
        sorted_hashes = []
        for name in sorted(self._frozen_tools.keys()):
            tool = self._frozen_tools[name]
            sorted_hashes.append(f"{name}:{tool.DEFINITION_HASH}")
        aggregate_data = "|".join(sorted_hashes)
        self._aggregate_hash = compute_hash(aggregate_data)

        # Seal the registry
        self._frozen = True
        self._staging = {}  # Clear staging area

        tool_count = len(self._frozen_tools)
        logger.info(
            f"[ToolRegistry] FROZEN. {tool_count} tools sealed. "
            f"Aggregate hash: {self._aggregate_hash[:16]}..."
        )

        return FrozenRegistry(self._frozen_tools, self._aggregate_hash)


class FrozenRegistry:
    """
    Immutable registry of frozen MCP tool definitions.

    Created by ToolRegistry.freeze(). Provides read-only access to
    tool definitions and integrity verification.

    Uses __slots__ to prevent adding new attributes and overrides
    __setattr__/__delattr__ to prevent mutation after initialization.
    """

    __slots__ = ("_tools", "_aggregate_hash", "_tool_names", "_init_done")

    def __init__(self, frozen_tools, aggregate_hash):
        # Use object.__setattr__ during init to bypass our frozen __setattr__
        object.__setattr__(self, "_tools", dict(frozen_tools))
        object.__setattr__(self, "_aggregate_hash", aggregate_hash)
        object.__setattr__(self, "_tool_names", tuple(sorted(frozen_tools.keys())))
        object.__setattr__(self, "_init_done", True)

    def __setattr__(self, name, value):
        if getattr(self, "_init_done", False):
            raise TypeError(
                f"FrozenRegistry is immutable: cannot set '{name}'. "
                f"The registry is sealed after freeze()."
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name):
        raise TypeError(
            f"FrozenRegistry is immutable: cannot delete '{name}'."
        )

    @property
    def tool_names(self):
        """Tuple of registered tool names (sorted)."""
        return self._tool_names

    @property
    def aggregate_hash(self):
        """SHA-256 hash over all tool definition hashes."""
        return self._aggregate_hash

    def get_tool(self, name):
        """
        Get a frozen tool definition by name.

        Args:
            name: Tool name.

        Returns:
            FrozenNamespace class for the tool.

        Raises:
            KeyError: If tool is not registered.
        """
        if name not in self._tools:
            raise KeyError(
                f"TOOL NOT FOUND: '{name}' is not in the frozen registry. "
                f"Registered tools: {list(self._tool_names)}"
            )
        return self._tools[name]

    def is_registered(self, name):
        """Check if a tool is registered."""
        return name in self._tools

    def verify_tool_integrity(self, name):
        """
        Verify a tool's definition has not been tampered with.

        Recomputes the SHA-256 hash from the tool's canonical JSON
        and compares against the stored hash.

        Args:
            name: Tool name to verify.

        Returns:
            tuple: (is_valid: bool, reason: str)
        """
        tool = self.get_tool(name)
        recomputed = compute_hash(tool.CANONICAL_JSON)
        # Use constant-time comparison to prevent timing attacks
        if hmac.compare_digest(recomputed, tool.DEFINITION_HASH):
            return True, f"Tool '{name}' integrity verified."
        else:
            return False, (
                f"INTEGRITY VIOLATION: Tool '{name}' hash mismatch. "
                f"Expected: {tool.DEFINITION_HASH[:16]}... "
                f"Got: {recomputed[:16]}..."
            )

    def verify_all_integrity(self):
        """
        Verify integrity of all tools and the aggregate hash.

        Returns:
            tuple: (all_valid: bool, results: list of (name, valid, reason))
        """
        results = []
        all_valid = True
        for name in self._tool_names:
            valid, reason = self.verify_tool_integrity(name)
            results.append((name, valid, reason))
            if not valid:
                all_valid = False

        # Verify aggregate
        sorted_hashes = []
        for name in self._tool_names:
            tool = self._tools[name]
            sorted_hashes.append(f"{name}:{tool.DEFINITION_HASH}")
        aggregate_data = "|".join(sorted_hashes)
        recomputed_aggregate = compute_hash(aggregate_data)
        if not hmac.compare_digest(recomputed_aggregate, self._aggregate_hash):
            all_valid = False
            results.append(("__aggregate__", False, "Aggregate hash mismatch."))
        else:
            results.append(("__aggregate__", True, "Aggregate hash verified."))

        return all_valid, results

    def get_tool_risk_level(self, name):
        """Get the risk level of a tool."""
        return self.get_tool(name).RISK_LEVEL

    def get_tool_schema(self, name, schema_type="output"):
        """Get the input or output schema for a tool."""
        tool = self.get_tool(name)
        if schema_type == "input":
            return tool.INPUT_SCHEMA
        return tool.OUTPUT_SCHEMA

    def __len__(self):
        return len(self._tools)

    def __repr__(self):
        return (
            f"FrozenRegistry(tools={len(self._tools)}, "
            f"hash={self._aggregate_hash[:16]}...)"
        )
