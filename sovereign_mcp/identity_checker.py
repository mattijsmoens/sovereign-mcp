"""
IdentityChecker — Caller Identity Verification (Check 9).
==========================================================
Verifies that the caller (agent, user, or service) is authorized
to invoke a specific tool. Uses frozen identity tokens stored in
FrozenNamespace. All comparisons use hmac.compare_digest to prevent
timing attacks.

Part of the SovereignShield 13 Audit Checks.
"""

import hashlib
import hmac
import logging
import types

logger = logging.getLogger(__name__)


class IdentityChecker:
    """
    Verify caller identity against frozen authorized identities.

    Usage:
        checker = IdentityChecker()
        checker.register_identity("agent-001", "secret-token-abc123")
        checker.freeze()

        # At runtime:
        allowed, reason = checker.verify("agent-001", "secret-token-abc123", "send_money")
    """

    def __init__(self):
        self._identities = {}  # identity_id -> {token_hash, allowed_tools}
        self.__frozen = False  # Name-mangled to prevent direct access

    def register_identity(self, identity_id, token, allowed_tools=None):
        """
        Register an authorized identity.

        Args:
            identity_id: Unique identifier for the caller.
            token: Secret token for authentication.
            allowed_tools: List of tool names this identity can invoke.
                          None means all tools.
        """
        if self.__frozen:
            raise RuntimeError("Cannot register identities after freeze.")

        # Validate token type
        if not isinstance(token, str) or not token:
            raise ValueError("Token must be a non-empty string.")

        # Store hash of token, never the raw token
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        self._identities[identity_id] = {
            "token_hash": token_hash,
            "allowed_tools": tuple(allowed_tools) if allowed_tools else None,
        }

    def freeze(self):
        """Freeze the identity registry. No more registrations allowed. Irreversible."""
        if self.__frozen:
            return  # Already frozen, no-op
        self.__frozen = True
        # Convert to immutable MappingProxyType — no new identities can be
        # injected via checker._identities["evil"] = {...} after freeze
        self._identities = types.MappingProxyType(dict(self._identities))
        logger.info(
            f"[IdentityChecker] Frozen. {len(self._identities)} identities registered."
        )

    def verify(self, identity_id, token, tool_name=None):
        """
        Verify a caller's identity and authorization.

        Args:
            identity_id: Claimed identity.
            token: Provided authentication token.
            tool_name: Tool being invoked (optional, for per-tool authorization).

        Returns:
            tuple: (authorized: bool, reason: str)
        """
        # Check identity exists
        identity = self._identities.get(identity_id)
        if identity is None:
            logger.warning(
                f"[IdentityChecker] DECLINED: Unknown identity '{identity_id}'"
            )
            return False, f"Unknown identity: '{identity_id}'."

        # Verify token (constant-time comparison)
        provided_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(provided_hash, identity["token_hash"]):
            logger.warning(
                f"[IdentityChecker] DECLINED: Invalid token for '{identity_id}'"
            )
            return False, f"Invalid authentication token for '{identity_id}'."

        # Check tool-level authorization
        if tool_name is not None and identity["allowed_tools"] is not None:
            if tool_name not in identity["allowed_tools"]:
                logger.warning(
                    f"[IdentityChecker] DECLINED: '{identity_id}' not authorized "
                    f"for tool '{tool_name}'"
                )
                return False, (
                    f"Identity '{identity_id}' is not authorized to invoke "
                    f"tool '{tool_name}'."
                )

        return True, f"Identity '{identity_id}' verified."

    @property
    def identity_count(self):
        return len(self._identities)

    @property
    def is_frozen(self):
        return self.__frozen
