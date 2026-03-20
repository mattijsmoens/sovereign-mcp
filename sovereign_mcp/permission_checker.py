"""
PermissionChecker — Deterministic Capability & Target Validation.
=================================================================
Checks whether a tool call is within the frozen permission set.
Binary lookup: the tool has the capability or it doesn't.

This is Step 3 of the runtime verification flow.
"""

import logging
import posixpath

logger = logging.getLogger(__name__)


class PermissionChecker:
    """
    Validate tool actions against frozen capability grants and allowed targets.
    """

    @classmethod
    def check(cls, tool_name, action, target, frozen_registry):
        """
        Check if a tool is allowed to perform an action on a target.

        Args:
            tool_name: Name of the tool.
            action: Action being attempted (e.g., "read_file", "send_money").
            target: Target resource (e.g., "/data/users.json", "api.example.com").
            frozen_registry: FrozenRegistry instance.

        Returns:
            tuple: (allowed: bool, reason: str)
        """
        # Step 1: Is the tool registered?
        if not frozen_registry.is_registered(tool_name):
            logger.warning(f"[PermissionChecker] DECLINED: Unknown tool '{tool_name}'")
            return False, f"Tool '{tool_name}' is not registered in the frozen registry."

        tool = frozen_registry.get_tool(tool_name)

        # Step 2: Verify tool integrity (hash check)
        is_valid, reason = frozen_registry.verify_tool_integrity(tool_name)
        if not is_valid:
            logger.critical(f"[PermissionChecker] INTEGRITY FAILURE: {reason}")
            return False, reason

        # Step 3: Check capability
        # Note: if CAPABILITIES is an empty tuple, NO actions are allowed
        if action not in tool.CAPABILITIES:
            logger.warning(
                f"[PermissionChecker] DECLINED: Tool '{tool_name}' does not have "
                f"capability '{action}'. Allowed: {list(tool.CAPABILITIES)}"
            )
            return False, (
                f"Tool '{tool_name}' does not have capability '{action}'. "
                f"Declared capabilities: {list(tool.CAPABILITIES)}"
            )

        # Step 4: Check target
        # Note: if ALLOWED_TARGETS is an empty tuple and a target is provided,
        # NO targets are allowed (same principle as empty CAPABILITIES)
        if target:
            # SECURITY: Normalize path to prevent traversal attacks
            # e.g. /data/../etc/passwd → /etc/passwd (no longer matches /data/*)
            normalized_target = posixpath.normpath(target)

            target_allowed = False
            for allowed_target in tool.ALLOWED_TARGETS:
                # Support prefix matching for paths and wildcard domains
                if allowed_target.endswith("*"):
                    prefix = allowed_target[:-1]
                    if normalized_target.startswith(prefix):
                        target_allowed = True
                        break
                elif normalized_target == allowed_target:
                    target_allowed = True
                    break

            if not target_allowed:
                logger.warning(
                    f"[PermissionChecker] DECLINED: Tool '{tool_name}' target "
                    f"'{target}' (normalized: '{normalized_target}') "
                    f"not in allowed targets: {list(tool.ALLOWED_TARGETS)}"
                )
                return False, (
                    f"Tool '{tool_name}' is not allowed to access '{target}'. "
                    f"Allowed targets: {list(tool.ALLOWED_TARGETS)}"
                )

        logger.debug(
            f"[PermissionChecker] ALLOWED: {tool_name} -> {action} on {target}"
        )
        return True, "Permission check passed."
