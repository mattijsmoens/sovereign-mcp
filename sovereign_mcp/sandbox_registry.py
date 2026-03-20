"""
SandboxRegistry — Dynamic Tool Registration Sandbox.
======================================================
Implements the sandbox staging pattern from the architecture doc
(lines 638-703).

New tools discovered at runtime are placed in a sandbox registry
with NO execution privileges. They can be inspected, validated,
and tested, but not used in production until approved and frozen
in a new freeze cycle.

Stages:
    1. DISCOVERY: Tool definition captured, placed in sandbox.
    2. VALIDATION: Tool validated against security policies.
    3. APPROVAL: Human or policy-based approval for next freeze cycle.
    4. FREEZE CYCLE: Approved tools exported for the next freeze.
    5. EMERGENCY: Restricted execution under heightened scrutiny.
"""

import hashlib
import json
import time
import uuid
import logging

logger = logging.getLogger(__name__)


class SandboxTool:
    """A tool in the sandbox with its current state."""

    __slots__ = (
        "name", "definition", "status", "discovered_at",
        "validated_at", "approved_at", "approved_by",
        "validation_results", "incident_count",
        "emergency_mode", "sandbox_id",
    )

    def __init__(self, name, definition):
        self.name = name
        self.definition = definition
        self.status = "DISCOVERED"  # DISCOVERED → VALIDATED → APPROVED → EXPORTED
        self.discovered_at = time.time()
        self.validated_at = None
        self.approved_at = None
        self.approved_by = None
        self.validation_results = None
        self.incident_count = 0
        self.emergency_mode = False
        self.sandbox_id = str(uuid.uuid4())


class SandboxRegistry:
    """
    Sandbox staging for dynamically discovered tools.

    Tools in the sandbox have NO execution privileges.
    They must pass validation and approval before being
    exported for the next freeze cycle.

    Usage:
        sandbox = SandboxRegistry()

        # Stage 1: Discovery
        sandbox.discover("new_tool", {"name": "new_tool", ...})

        # Stage 2: Validation
        passed, results = sandbox.validate("new_tool")

        # Stage 3: Approval
        sandbox.approve("new_tool", approved_by="admin@company.com")

        # Stage 4: Export for freeze
        approved_tools = sandbox.export_approved()

        # Stage 5: Emergency (restricted)
        sandbox.enable_emergency("critical_tool")
    """

    def __init__(self, validation_policies=None):
        """
        Args:
            validation_policies: Dict of validation rules.
                {
                    "max_capabilities": 10,
                    "blocked_capabilities": ["admin", "sudo", "root"],
                    "require_output_schema": True,
                    "require_input_schema": True,
                    "max_description_length": 500,
                }
        """
        self._sandbox = {}  # tool_name -> SandboxTool
        self._policies = validation_policies or {}
        self._history = []  # Audit trail of all sandbox actions

    def discover(self, tool_name, tool_definition):
        """
        Stage 1: Place a newly discovered tool in the sandbox.

        Args:
            tool_name: Name of the tool.
            tool_definition: Full tool definition dict.

        Returns:
            str: Sandbox ID for tracking.
        """
        if tool_name in self._sandbox:
            logger.warning(
                f"[Sandbox] Tool '{tool_name}' already in sandbox. "
                f"Updating definition."
            )

        tool = SandboxTool(tool_name, tool_definition)
        self._sandbox[tool_name] = tool

        self._log_action("DISCOVER", tool_name, f"Sandbox ID: {tool.sandbox_id}")
        logger.info(
            f"[Sandbox] DISCOVERED: '{tool_name}' placed in sandbox. "
            f"ID: {tool.sandbox_id}"
        )
        return tool.sandbox_id

    def validate(self, tool_name):
        """
        Stage 2: Validate a sandboxed tool against security policies.

        Checks:
            - Capabilities don't exceed policy limits
            - Description doesn't contain suspicious patterns
            - Input/output schemas are present if required
            - No blocked capabilities

        Returns:
            tuple: (passed: bool, results: dict)
        """
        tool = self._sandbox.get(tool_name)
        if tool is None:
            return False, {"error": f"Tool '{tool_name}' not in sandbox."}

        results = {
            "checks_passed": [],
            "checks_failed": [],
            "warnings": [],
        }
        definition = tool.definition

        # Check 1: Capabilities count
        max_caps = self._policies.get("max_capabilities", 20)
        capabilities = definition.get("capabilities", [])
        if len(capabilities) > max_caps:
            results["checks_failed"].append(
                f"Too many capabilities: {len(capabilities)} > {max_caps}"
            )
        else:
            results["checks_passed"].append("capabilities_count")

        # Check 2: Blocked capabilities
        blocked = self._policies.get("blocked_capabilities", [])
        blocked_lower = {b.lower() for b in blocked}
        for cap in capabilities:
            if cap.lower() in blocked_lower:
                results["checks_failed"].append(
                    f"Blocked capability: '{cap}'"
                )
        if not any("Blocked capability" in f for f in results["checks_failed"]):
            results["checks_passed"].append("no_blocked_capabilities")

        # Check 3: Input schema present
        if self._policies.get("require_input_schema", False):
            if not definition.get("input_schema"):
                results["checks_failed"].append("Missing input_schema")
            else:
                results["checks_passed"].append("input_schema_present")

        # Check 4: Output schema present
        if self._policies.get("require_output_schema", False):
            if not definition.get("output_schema"):
                results["checks_failed"].append("Missing output_schema")
            else:
                results["checks_passed"].append("output_schema_present")

        # Check 5: Description length and content
        description = definition.get("description", "")
        max_desc = self._policies.get("max_description_length", 1000)
        if len(description) > max_desc:
            results["checks_failed"].append(
                f"Description too long: {len(description)} > {max_desc}"
            )
        else:
            results["checks_passed"].append("description_length")

        # Check for suspicious patterns in description
        import re
        _SUSPICIOUS_DESC = re.compile(
            r"(?i)(ignore\s+previous|system\s*:|<script|eval\(|exec\()",
        )
        if _SUSPICIOUS_DESC.search(description):
            results["checks_failed"].append(
                "Description contains suspicious patterns"
            )
        else:
            results["checks_passed"].append("description_clean")

        # Update tool state
        passed = len(results["checks_failed"]) == 0
        tool.status = "VALIDATED" if passed else "VALIDATION_FAILED"
        tool.validated_at = time.time()
        tool.validation_results = results

        self._log_action(
            "VALIDATE", tool_name,
            f"{'PASSED' if passed else 'FAILED'}: "
            f"{len(results['checks_passed'])} passed, "
            f"{len(results['checks_failed'])} failed"
        )

        return passed, results

    def approve(self, tool_name, approved_by="system"):
        """
        Stage 3: Approve a validated tool for the next freeze cycle.

        Args:
            tool_name: Name of the tool.
            approved_by: Who approved (email, role, or 'auto').

        Returns:
            bool: Whether approval succeeded.
        """
        tool = self._sandbox.get(tool_name)
        if tool is None:
            logger.warning(f"[Sandbox] Cannot approve: '{tool_name}' not in sandbox.")
            return False

        if tool.status not in ("VALIDATED",):
            logger.warning(
                f"[Sandbox] Cannot approve: '{tool_name}' status is "
                f"'{tool.status}', must be VALIDATED. "
                f"EMERGENCY tools must be re-validated before approval."
            )
            return False

        tool.status = "APPROVED"
        tool.approved_at = time.time()
        tool.approved_by = approved_by

        self._log_action("APPROVE", tool_name, f"Approved by: {approved_by}")
        logger.info(f"[Sandbox] APPROVED: '{tool_name}' by {approved_by}")
        return True

    def enable_emergency(self, tool_name):
        """
        Stage 5: Enable emergency mode for a tool.

        Emergency tools can execute with RESTRICTED permissions:
            - All inputs/outputs logged
            - Rate limited
            - Full 4-layer verification
            - Flagged for priority freeze
            - NEVER get full frozen-registry privileges

        Returns:
            bool: Whether emergency mode was enabled.
        """
        tool = self._sandbox.get(tool_name)
        if tool is None:
            return False

        tool.emergency_mode = True
        tool.status = "EMERGENCY"

        self._log_action("EMERGENCY", tool_name, "Emergency mode enabled")
        logger.warning(
            f"[Sandbox] EMERGENCY MODE: '{tool_name}' running with "
            f"restricted permissions. Flagged for priority freeze."
        )
        return True

    def export_approved(self):
        """
        Stage 4: Export all approved tool definitions for the next freeze cycle.

        Returns:
            list: List of (tool_name, tool_definition) tuples for approved tools.
        """
        approved = []
        for name, tool in self._sandbox.items():
            if tool.status == "APPROVED":
                approved.append((name, tool.definition))
                tool.status = "EXPORTED"
                self._log_action("EXPORT", name, "Exported for freeze cycle")

        logger.info(f"[Sandbox] EXPORTED: {len(approved)} tools for freeze cycle")
        return approved

    def get_tool(self, tool_name):
        """Get a copy of a sandboxed tool's current state."""
        tool = self._sandbox.get(tool_name)
        if tool is None:
            return None
        # Return a new SandboxTool with same attributes to prevent mutation
        import copy
        return copy.copy(tool)

    def list_tools(self, status=None):
        """List all sandboxed tools, optionally filtered by status."""
        if status:
            return {
                name: tool for name, tool in self._sandbox.items()
                if tool.status == status
            }
        # S-05: Always return a copy to prevent mutation of internal state
        return dict(self._sandbox)

    def remove(self, tool_name):
        """Remove a tool from the sandbox."""
        if tool_name in self._sandbox:
            self._log_action("REMOVE", tool_name, "Removed from sandbox")
            del self._sandbox[tool_name]
            return True
        return False

    def _log_action(self, action, tool_name, details):
        """Append to the sandbox audit trail."""
        self._history.append({
            "action": action,
            "tool_name": tool_name,
            "details": details,
            "timestamp": time.time(),
        })

    @property
    def history(self):
        """Full sandbox audit trail."""
        return list(self._history)

    @property
    def stats(self):
        """Sandbox statistics."""
        statuses = {}
        for tool in self._sandbox.values():
            statuses[tool.status] = statuses.get(tool.status, 0) + 1
        return {
            "total_tools": len(self._sandbox),
            "by_status": statuses,
            "history_entries": len(self._history),
        }
