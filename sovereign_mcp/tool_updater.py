"""
ToolUpdater — Safe Tool Update with Blue-Green Freeze Rotation.
================================================================
Handles legitimate tool updates (new version, updated capabilities)
without compromising the frozen reference integrity.

Architecture Lines 705-751:
    1. Current state: Process A running with frozen v1 definitions
    2. Update arrives: v2 placed in sandbox, validated against v1
    3. Approval: auto/manual based on change type
    4. Blue-green deployment: new process with v2 definitions
    5. Rollback guarantee: v1 preserved until v2 confirmed

Key principle: The frozen reference is NEVER modified in place.
Updates create a NEW frozen reference in a NEW process.
"""

import hashlib
import json
import copy
import time
import logging

logger = logging.getLogger(__name__)


class ToolUpdateAnalysis:
    """
    Result of analyzing a tool update (v1 → v2 diff).

    Attributes:
        tool_name: Name of the tool being updated.
        changes: List of change descriptions.
        capabilities_added: New capabilities in v2 not in v1.
        capabilities_removed: Capabilities in v1 removed in v2.
        schema_changed: Whether the output schema structure changed.
        schema_fields_added: New fields in v2 output schema.
        schema_fields_removed: Fields removed from v1 output schema.
        schema_types_changed: Fields whose types changed.
        requires_manual_approval: Whether human review is needed.
        auto_approve_reason: Reason for auto-approval (if applicable).
        risk_level_changed: Whether the risk level changed.
    """

    def __init__(self, tool_name):
        self.tool_name = tool_name
        self.changes = []
        self.capabilities_added = []
        self.capabilities_removed = []
        self.schema_changed = False
        self.schema_fields_added = []
        self.schema_fields_removed = []
        self.schema_types_changed = []
        self.requires_manual_approval = False
        self.auto_approve_reason = None
        self.risk_level_changed = False
        self.v1_hash = None
        self.v2_hash = None
        self.timestamp = time.time()

    @property
    def is_safe_update(self):
        """Whether this update can be auto-approved."""
        return not self.requires_manual_approval

    def to_dict(self):
        """Serialize to dict for logging."""
        return {
            "tool_name": self.tool_name,
            "changes": self.changes,
            "capabilities_added": self.capabilities_added,
            "capabilities_removed": self.capabilities_removed,
            "schema_changed": self.schema_changed,
            "schema_fields_added": self.schema_fields_added,
            "schema_fields_removed": self.schema_fields_removed,
            "schema_types_changed": self.schema_types_changed,
            "requires_manual_approval": self.requires_manual_approval,
            "auto_approve_reason": self.auto_approve_reason,
            "risk_level_changed": self.risk_level_changed,
            "v1_hash": self.v1_hash,
            "v2_hash": self.v2_hash,
            "timestamp": self.timestamp,
        }


class ToolUpdater:
    """
    Safe tool update process with blue-green freeze rotation.

    Analyzes differences between v1 and v2 tool definitions,
    determines approval requirements, and manages the update
    lifecycle. The frozen reference is NEVER modified in place.

    Usage:
        updater = ToolUpdater()

        # Analyze an update
        analysis = updater.analyze_update(v1_definition, v2_definition)

        # Check if auto-approvable
        if analysis.is_safe_update:
            updater.approve_update(analysis)
        else:
            # Requires manual review
            print(f"Manual approval needed: {analysis.changes}")

        # Prepare new freeze cycle
        updated_definitions = updater.prepare_freeze_cycle(
            current_frozen_registry, approved_updates
        )

        # Create snapshot for rollback
        snapshot = updater.create_rollback_snapshot(current_frozen_registry)

        # Rollback if needed
        recovered_definitions = updater.rollback(snapshot)
    """

    def __init__(self):
        self._approved_updates = {}    # tool_name → ToolUpdateAnalysis
        self._pending_updates = {}     # tool_name → ToolUpdateAnalysis
        self._update_history = []      # List of all update analyses
        self._rollback_snapshots = {}  # snapshot_id → snapshot data

        logger.info("[ToolUpdater] Initialized.")

    def analyze_update(self, v1_definition, v2_definition):
        """
        Analyze differences between v1 and v2 tool definitions.

        Architecture Lines 718-726:
            a) What changed? (diff analysis)
            b) Were capabilities added? (requires review)
            c) Were capabilities removed? (safe, auto-approve)
            d) Did the output schema change? (requires schema migration)

        Args:
            v1_definition: Dict of the current (frozen) tool definition.
            v2_definition: Dict of the new tool definition.

        Returns:
            ToolUpdateAnalysis with all detected changes.
        """
        name = v2_definition.get("name", v1_definition.get("name", "unknown"))
        analysis = ToolUpdateAnalysis(name)

        # Compute hashes
        analysis.v1_hash = self._compute_definition_hash(v1_definition)
        analysis.v2_hash = self._compute_definition_hash(v2_definition)

        # If hashes match, nothing changed
        if analysis.v1_hash == analysis.v2_hash:
            analysis.auto_approve_reason = "No changes detected (hash match)."
            return analysis

        # --- Check capabilities ---
        v1_caps = set(v1_definition.get("capabilities") or [])
        v2_caps = set(v2_definition.get("capabilities") or [])

        added_caps = v2_caps - v1_caps
        removed_caps = v1_caps - v2_caps

        if added_caps:
            analysis.capabilities_added = sorted(added_caps)
            analysis.changes.append(
                f"Capabilities ADDED: {sorted(added_caps)}"
            )
            # Capability expansion requires manual approval (Line 733-734)
            analysis.requires_manual_approval = True

        if removed_caps:
            analysis.capabilities_removed = sorted(removed_caps)
            analysis.changes.append(
                f"Capabilities REMOVED: {sorted(removed_caps)}"
            )
            # Capability removal is safe (Line 724)

        # --- Check output schema ---
        v1_output = v1_definition.get("output_schema") or {}
        v2_output = v2_definition.get("output_schema") or {}

        v1_fields = set(v1_output.keys())
        v2_fields = set(v2_output.keys())

        new_fields = v2_fields - v1_fields
        removed_fields = v1_fields - v2_fields

        if new_fields:
            analysis.schema_fields_added = sorted(new_fields)
            analysis.schema_changed = True
            analysis.changes.append(
                f"Output schema fields ADDED: {sorted(new_fields)}"
            )
            # Schema-breaking update (Line 731-732)
            analysis.requires_manual_approval = True

        if removed_fields:
            analysis.schema_fields_removed = sorted(removed_fields)
            analysis.schema_changed = True
            analysis.changes.append(
                f"Output schema fields REMOVED: {sorted(removed_fields)}"
            )
            analysis.requires_manual_approval = True

        # Check type changes in shared fields
        shared_fields = v1_fields & v2_fields
        for field in shared_fields:
            v1_type = (v1_output[field] or {}).get("type") if isinstance(v1_output.get(field), dict) else None
            v2_type = (v2_output[field] or {}).get("type") if isinstance(v2_output.get(field), dict) else None
            if v1_type != v2_type:
                analysis.schema_types_changed.append(
                    f"{field}: {v1_type} → {v2_type}"
                )
                analysis.schema_changed = True
                analysis.changes.append(
                    f"Output field '{field}' type changed: {v1_type} → {v2_type}"
                )
                analysis.requires_manual_approval = True

        # --- Check input schema ---
        v1_input = v1_definition.get("input_schema") or {}
        v2_input = v2_definition.get("input_schema") or {}

        if v1_input != v2_input:
            analysis.changes.append("Input schema modified")
            # Input schema changes can introduce new attack surface
            analysis.requires_manual_approval = True

        # --- Check risk level ---
        v1_risk = v1_definition.get("risk_level", "HIGH")
        v2_risk = v2_definition.get("risk_level", "HIGH")

        if v1_risk != v2_risk:
            analysis.risk_level_changed = True
            analysis.changes.append(
                f"Risk level changed: {v1_risk} → {v2_risk}"
            )
            # Risk level changes always require manual review
            analysis.requires_manual_approval = True

        # --- Check allowed targets ---
        v1_targets = set(v1_definition.get("allowed_targets") or [])
        v2_targets = set(v2_definition.get("allowed_targets") or [])

        new_targets = v2_targets - v1_targets
        if new_targets:
            analysis.changes.append(
                f"Allowed targets EXPANDED: {sorted(new_targets)}"
            )
            analysis.requires_manual_approval = True

        removed_targets = v1_targets - v2_targets
        if removed_targets:
            analysis.changes.append(
                f"Allowed targets REDUCED: {sorted(removed_targets)}"
            )

        # --- Check description ---
        v1_desc = v1_definition.get("description", "")
        v2_desc = v2_definition.get("description", "")
        if v1_desc != v2_desc:
            analysis.changes.append("Description updated")

        # --- Auto-approve determination ---
        # Schema-compatible updates with only removals → auto-approve (Line 729-730)
        if not analysis.requires_manual_approval:
            if analysis.changes:
                analysis.auto_approve_reason = (
                    "Schema-compatible update with no capability expansion. "
                    "Safe for auto-approval."
                )
            else:
                analysis.auto_approve_reason = "No significant changes."

        # Store for history
        self._pending_updates[name] = analysis
        self._update_history.append(analysis)

        logger.info(
            f"[ToolUpdater] Analyzed update for '{name}': "
            f"{len(analysis.changes)} changes, "
            f"manual_required={analysis.requires_manual_approval}"
        )

        return analysis

    def approve_update(self, analysis, approver="auto"):
        """
        Approve a pending tool update.

        Args:
            analysis: ToolUpdateAnalysis to approve.
            approver: Identity of the approver ("auto" or human identity).

        Returns:
            tuple: (approved: bool, reason: str)
        """
        name = analysis.tool_name

        if name not in self._pending_updates:
            return False, f"No pending update for tool '{name}'."

        if analysis.requires_manual_approval and approver == "auto":
            return False, (
                f"Tool '{name}' requires manual approval. "
                f"Changes: {analysis.changes}"
            )

        # Move from pending to approved
        self._pending_updates.pop(name, None)
        self._approved_updates[name] = {
            "analysis": analysis,
            "approver": approver,
            "approved_at": time.time(),
        }

        logger.info(
            f"[ToolUpdater] Update APPROVED for '{name}' by {approver}. "
            f"Changes: {len(analysis.changes)}"
        )

        return True, f"Update approved for '{name}'."

    def prepare_freeze_cycle(self, current_definitions, approved_updates=None):
        """
        Prepare tool definitions for a new freeze cycle.

        Merges current frozen definitions with approved updates to create
        the input for the next FrozenNamespace.

        Architecture Lines 677-688:
            a) Process initiates graceful shutdown
            b) New FrozenNamespace is constructed with existing + approved tools
            c) All definitions are frozen and hash-sealed
            d) Process restarts with updated frozen registry

        Args:
            current_definitions: Dict of tool_name → definition dict
                                 (from current frozen registry).
            approved_updates: Optional dict of tool_name → new definition dict.
                              If None, uses internally tracked approved updates.

        Returns:
            Dict of tool_name → definition dict for the new freeze cycle.
        """
        # Start with deep copy of current definitions
        new_definitions = copy.deepcopy(current_definitions)

        # Apply approved updates
        updates = approved_updates or {}

        # Also merge any internally approved updates
        for name, analysis in self._approved_updates.items():
            if name not in updates:
                # Internal update tracked but definition must be provided
                logger.warning(
                    f"[ToolUpdater] Approved update for '{name}' but "
                    f"no v2 definition provided. Skipping."
                )

        for name, new_def in updates.items():
            new_definitions[name] = copy.deepcopy(new_def)

        logger.info(
            f"[ToolUpdater] Freeze cycle prepared. "
            f"{len(new_definitions)} tools, "
            f"{len(updates)} updates applied."
        )

        return new_definitions

    def create_rollback_snapshot(self, frozen_registry):
        """
        Create a snapshot of the current frozen registry for rollback.

        Architecture Lines 744-747:
            Process A's frozen definitions are preserved until Process B
            is confirmed. If v2 causes issues, instant rollback to v1.

        Args:
            frozen_registry: The current FrozenRegistry instance.

        Returns:
            str: Snapshot ID for rollback.
        """
        snapshot_id = hashlib.sha256(
            f"{time.time()}:{frozen_registry.aggregate_hash}".encode()
        ).hexdigest()[:16]

        # Store tool definitions for rollback
        tool_defs = {}
        for name in frozen_registry.tool_names:
            tool = frozen_registry.get_tool(name)
            tool_defs[name] = {
                "name": name,
                "description": tool.DESCRIPTION,
                "input_schema": tool.INPUT_SCHEMA,
                "output_schema": tool.OUTPUT_SCHEMA,
                "capabilities": list(tool.CAPABILITIES),
                "allowed_targets": list(tool.ALLOWED_TARGETS),
                "risk_level": tool.RISK_LEVEL,
                "verification_source": tool.VERIFICATION_SOURCE,
                "value_constraints": tool.VALUE_CONSTRAINTS,
                "approval_thresholds": tool.APPROVAL_THRESHOLDS,
                "rate_limits": getattr(tool, 'RATE_LIMITS', None),
                "allowed_domains": getattr(tool, 'ALLOWED_DOMAINS', None),
                "definition_hash": getattr(tool, 'DEFINITION_HASH', None),
            }

        self._rollback_snapshots[snapshot_id] = {
            "snapshot_id": snapshot_id,
            "timestamp": time.time(),
            "aggregate_hash": frozen_registry.aggregate_hash,
            "tool_count": len(tool_defs),
            "definitions": tool_defs,
        }

        logger.info(
            f"[ToolUpdater] Rollback snapshot created: {snapshot_id} "
            f"({len(tool_defs)} tools, "
            f"hash: {frozen_registry.aggregate_hash[:16]}...)"
        )

        return snapshot_id

    def rollback(self, snapshot_id):
        """
        Rollback to a previous frozen state.

        Args:
            snapshot_id: ID from create_rollback_snapshot().

        Returns:
            Dict of tool_name → definition dict (for re-freeze).

        Raises:
            KeyError: If snapshot not found.
        """
        snapshot = self._rollback_snapshots.get(snapshot_id)
        if not snapshot:
            raise KeyError(
                f"Rollback snapshot '{snapshot_id}' not found. "
                f"Available: {list(self._rollback_snapshots.keys())}"
            )

        logger.warning(
            f"[ToolUpdater] ROLLBACK to snapshot {snapshot_id}. "
            f"Restoring {snapshot['tool_count']} tools from "
            f"aggregate hash {snapshot['aggregate_hash'][:16]}..."
        )

        return copy.deepcopy(snapshot["definitions"])

    def get_update_history(self, tool_name=None, limit=50):
        """
        Get update analysis history.

        Args:
            tool_name: Optional filter by tool name.
            limit: Maximum results.

        Returns:
            List of ToolUpdateAnalysis.to_dict() results.
        """
        results = []
        for analysis in reversed(self._update_history):
            if tool_name and analysis.tool_name != tool_name:
                continue
            results.append(analysis.to_dict())
            if len(results) >= limit:
                break
        return results

    def _compute_definition_hash(self, definition):
        """Compute SHA-256 hash of a tool definition for comparison."""
        canonical = json.dumps(
            definition, sort_keys=True, separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
