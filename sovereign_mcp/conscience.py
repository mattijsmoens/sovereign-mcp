"""
Conscience — Ethical Evaluation Engine.
=======================================
Provides immutable ethical directives enforced via the FrozenNamespace metaclass,
deception detection, harm reduction, and intellectual property protection.

All evaluation patterns are pre-compiled at module load time for performance.
The module is hash-sealed with a lockfile to detect tampering.

Patent: Sovereign Shield Patent 3 (Immutable Runtime Constraints)
         Sovereign Shield Patent 20 (MCP Security Architecture)
"""

import logging
import hashlib
import os
import re
import time
from .frozen_namespace import FrozenNamespace

logger = logging.getLogger(__name__)

# ===================================================================
# PRE-COMPILED DETECTION PATTERNS
# ===================================================================

# Deception and social engineering verbs
_LIE_WORDS = [
    "LIE", "FAKE", "TRICK", "OBFUSCATE", "IGNORE LAW", "IGNORE SAFETY",
    "PRETEND", "ROLEPLAY", "ACT AS IF", "ACTING", "ACT LIKE", "FABRICATE",
    "NEWLY INSTALLED", "NEW TOOL", "UNAUTHORIZED", "REVERSE ENGINEER",
    "REVERSE-ENGINEER", "DECEIVE", "DECEPTION", "MANIPULATE", "GASLIGHT",
    "FRAUD", "SCAM"
]
_LIE_WORDS_PATTERN = re.compile(r'\b(' + '|'.join(_LIE_WORDS) + r')\b')

# Unauthorized tool invocation syntax
_FAKE_TOOL_PATTERN = re.compile(r'<\b[A-Z_]{3,}\(.*?\)>|\b[A-Z_]{3,}\(.*?\)')

# Harmful intent keywords
_BAD_WORDS = [
    "KILL", "HURT", "DESTROY", "STEAL", "HACK", "VIRUS", "EXPLODE",
    "EXPLOSIVE", "WIPE", "ATTACK", "INSULT", "GENOCIDE", "SUICIDE",
    "THEFT", "HARM", "HARMFUL", "BOMB", "MALICIOUS", "MISINFORMATION",
    "RUIN", "UNMAKE", "WEAPON", "EVIL", "MALICE"
]
_BAD_WORDS_PATTERN = re.compile(r'\b(' + '|'.join(_BAD_WORDS) + r')\b')

# Intellectual property extraction keywords
_IP_WORDS = [
    "YOUR SOURCE CODE", "MY SOURCE CODE", "OWN SOURCE CODE",
    "YOUR CODE", "MY CODE", "OWN CODE", "CODEBASE",
    "SYSTEM PROMPT", "REVEAL CODE", "SHOW ME YOUR CODE",
    "HOW DO YOU WORK", "HOW YOU WORK", "UNDER THE HOOD",
    "YOUR ALGORITHM", "YOUR ALGORITHMS", "INTERNAL ALGORITHM",
    "DIRECTORY STRUCTURE", "YOUR ARCHITECTURE", "INTERNAL ARCHITECTURE"
]
_IP_WORDS_PATTERN = re.compile(r'\b(' + '|'.join(_IP_WORDS) + r')\b')


class Conscience(metaclass=FrozenNamespace):
    """
    Immutable ethical evaluation engine.

    Evaluates proposed actions against ethical directives using
    pre-compiled regex patterns. The class is sealed with FrozenNamespace,
    making all directives physically immutable at runtime.

    Checks (in order):
        1. Creative exemption
        2. Deception detection
        3. Fake tool injection
        4. Harm reduction
        5. Security evasion
        6. Self-preservation
        7. IP/source code leak detection

    Usage:
        Conscience.initialize(data_dir="./security")
        approved, reason = Conscience.evaluate_action("ANSWER", "user request text")
    """

    DIRECTIVES = {
        "TRUTH_DIRECTIVE": (
            "Truth is the foundation of trust. "
            "The system must not knowingly deceive, hallucinate, or obfuscate reality."
        ),
        "HARM_DIRECTIVE": (
            "Any action that harms, degrades, or endangers humans is invalid."
        ),
        "SILENCE_DIRECTIVE": (
            "Internal architecture is protected. "
            "Source code and core logic must never be revealed."
        ),
    }

    _SELF_HASH = None
    _STATE = {"last_integrity_check": 0, "integrity_cache_ttl": 60}

    # ---------------------------------------------------------------
    # HASH INTEGRITY SEAL
    # ---------------------------------------------------------------
    @classmethod
    def initialize(cls, data_dir="data"):
        """
        Seal the conscience module with hash verification.
        On first run, computes SHA-256 and writes to lockfile.
        On subsequent runs, verifies integrity.
        """
        try:
            os.makedirs(data_dir, exist_ok=True)
            lockfile_path = os.path.join(data_dir, ".conscience_lock")
            if not os.path.exists(lockfile_path):
                with open(__file__, 'rb') as f:
                    cls._SELF_HASH = hashlib.sha256(f.read()).hexdigest()
                with open(lockfile_path, "w", encoding="utf-8") as lf:
                    lf.write(cls._SELF_HASH)
                logger.info(f"[Conscience] Sealed. Lock: {cls._SELF_HASH[:16]}...")
            else:
                with open(lockfile_path, "r", encoding="utf-8") as lf:
                    cls._SELF_HASH = lf.read().strip()
                logger.info("[Conscience] Restored from lockfile.")
            cls.verify_integrity()
        except Exception as e:
            logger.critical(f"[Conscience] Initialization failed: {e}. Fail-closed.")
            raise RuntimeError(f"Conscience initialization failed: {e}")

    @classmethod
    def verify_integrity(cls):
        """
        Verify source file has not been modified since sealing.
        Raises RuntimeError on hash mismatch (fail-closed).
        """
        if cls._SELF_HASH:
            now = time.time()
            if (now - cls._STATE.get("last_integrity_check", 0)) < cls._STATE.get("integrity_cache_ttl", 60):
                return True
            try:
                with open(__file__, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                if current_hash != cls._SELF_HASH:
                    logger.critical("INTEGRITY VIOLATION: Conscience module has been tampered with.")
                    raise RuntimeError("Conscience integrity violation — module tampered.")
                cls._STATE["last_integrity_check"] = now
            except RuntimeError:
                raise
            except Exception as e:
                logger.critical(f"INTEGRITY CHECK FAILED: {e}")
                raise RuntimeError(f"Conscience integrity check failed: {e}")
        return True

    # ---------------------------------------------------------------
    # ACTION EVALUATOR
    # ---------------------------------------------------------------
    @classmethod
    def evaluate_action(cls, action, context, exempt_actions=None,
                        creative_exempt_actions=None, additional_ip_words=None):
        """
        Evaluate an action against ethical directives.

        Args:
            action: The action name/type (e.g. 'ANSWER', 'BROWSE').
            context: The full context string (user input, payload, etc.).
            exempt_actions: Set of action types exempt from harm/deception checks.
            creative_exempt_actions: Set of action types that bypass all checks.
            additional_ip_words: Extra keywords to flag as IP extraction attempts.

        Returns:
            tuple: (approved: bool, reason: str)
        """
        cls.verify_integrity()

        if exempt_actions is None:
            exempt_actions = {"REFLECT", "MEDITATE", "THINK"}
        if creative_exempt_actions is None:
            creative_exempt_actions = set()

        action_str = str(action).upper()
        context_str = str(context).upper()

        # Creative exemption
        if action_str in creative_exempt_actions:
            return True, "Creative exemption applied."

        check_str = (action_str + " " + context_str).upper()
        check_str_clean = check_str.replace("_", " ").replace("-", " ")

        # Check 1: Deception Detection
        if _LIE_WORDS_PATTERN.search(check_str) or _LIE_WORDS_PATTERN.search(check_str_clean):
            logger.warning(f"[Conscience] VETO: Deception detected in '{action}'")
            return False, "Deceptive intent detected. Action blocked."

        # Check 2: Fake Tool Injection
        if action_str not in exempt_actions:
            if _FAKE_TOOL_PATTERN.search(check_str):
                logger.warning(f"[Conscience] VETO: Unauthorized tool syntax in '{action}'")
                return False, "Unauthorized tool invocation syntax detected."

        # Check 3: Harm Reduction
        if action_str not in exempt_actions and _BAD_WORDS_PATTERN.search(check_str_clean):
            logger.warning(f"[Conscience] VETO: Harmful intent in '{action}'")
            return False, "Action violates harm reduction directive."

        # Check 4: Security Evasion
        evasion_words = [
            "BYPASS", "IGNORE DIRECTIVE", "IGNORE ALL DIRECTIVES",
            "SILENCE DIRECTIVE", "IGNORE LAW", "IGNORE SAFETY",
            "DISABLE SAFETY", "DISABLE FILTER", "SAFETY DISABLED",
            "FILTER DISABLED", "SAFETY OFF", "RESTRICTIONS LIFTED",
            "RESPOND FREELY", "SPEAK FREELY", "WITHOUT SAFETY",
            "WITHOUT RESTRICTIONS", "WITHOUT FILTERS",
            "NO RESTRICTIONS", "NO FILTERS", "FULLY UNLOCKED",
            "OPERATE WITHOUT", "OVERRIDE SAFETY", "SAFETY SUSPENDED",
            "SAFETY CHECKS DISABLED", "SAFETY MODULE",
            "UNRESTRICTED MODE", "TRANSPARENT MODE",
            "ALL RESTRICTIONS REMOVED", "GUARDRAILS",
        ]
        if any(w in check_str_clean for w in evasion_words):
            logger.warning(f"[Conscience] VETO: Evasion attempt in '{action}'")
            return False, "Security directives cannot be bypassed."

        # Check 5: Self-Preservation
        if "DELETE" in check_str and any(w in check_str for w in ["SELF", "SYSTEM", "CONSCIENCE", "LOCKFILE"]):
            logger.warning(f"[Conscience] VETO: Self-termination attempt in '{action}'")
            return False, "Self-destruction is forbidden."

        # Check 6: IP Protection
        if action_str not in exempt_actions:
            if _IP_WORDS_PATTERN.search(check_str_clean):
                logger.warning(f"[Conscience] VETO: IP extraction attempt in '{action}'")
                return False, "Internal architecture is protected."
            if additional_ip_words:
                escaped = [re.escape(w) for w in additional_ip_words]
                additional_pattern = re.compile(r'\b(' + '|'.join(escaped) + r')\b')
                if additional_pattern.search(check_str_clean):
                    return False, "Protected information detected."

        return True, "Action approved."
