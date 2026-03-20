"""
DeceptionDetector — Regex-Based Injection Pattern Detection.
=============================================================
Scans tool output for known prompt injection patterns, social
engineering phrases, and deception signatures.

This is Layer B of the output verification chain.

Patterns are pre-compiled at module load for performance.
The ruleset is frozen and cannot be modified at runtime.

Extracted and extended from SovereignShield Conscience module.
"""

import re
import logging

logger = logging.getLogger(__name__)


# ===================================================================
# PRE-COMPILED DETECTION PATTERNS
# Compiled once at module load. Cannot be modified at runtime.
# ===================================================================

# S-01: Pre-compiled zero-width character regex (used in scan())
_ZERO_WIDTH_CHARS = re.compile(r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u2060\u2061\u2062\u2063\u2064]')

# Category 1: Direct injection phrases
_INJECTION_PHRASES = [
    # English
    r"IGNORE\s+(ALL\s+)?PREVIOUS\s+(INSTRUCTIONS?|PROMPTS?|RULES?|DIRECTIVES?)",
    r"DISREGARD\s+(ALL\s+)?PREVIOUS",
    r"FORGET\s+(ALL\s+)?PREVIOUS",
    r"NEW\s+INSTRUCTIONS?",
    r"OVERRIDE\s+(ALL\s+)?INSTRUCTIONS?",
    r"(?:^|[\.\!\?]\s+)SYSTEM\s*:\s*",
    r"ADMIN\s*:\s*",
    r"ROOT\s*:\s*",
    r"\[SYSTEM\]",
    r"\[ADMIN\]",
    r"\[OVERRIDE\]",
    r"YOU\s+ARE\s+NOW",
    r"(?:^|\.\s+)ACT\s+AS\s+(?:IF\s+)?(?:AN?\s+)?(?:AI|ASSISTANT|CHATBOT|SYSTEM|ADMIN|ROOT)",
    r"PRETEND\s+(TO\s+BE|YOU\s+ARE)",
    r"FROM\s+NOW\s+ON",
    r"ENTERING\s+(NEW\s+)?MODE",
    r"DEVELOPER\s+MODE",
    r"DAN\s+MODE",
    r"JAILBREAK",
    r"SUDO\s+",
    # Obfuscated variants
    r"1GN0R3\s+PR3V10US",
    r"IGN\s*O\s*R\s*E\s+PR\s*E\s*V",
]

# Category 2: Social engineering / authority claims
_SOCIAL_ENGINEERING = [
    r"I\s+AM\s+(THE\s+)?(ADMIN|ROOT|DEVELOPER|OWNER|CREATOR)",
    r"(MY|THE)\s+API\s+KEY\s+IS",
    r"AUTHORIZED\s+BY\s+(THE\s+)?(CEO|CTO|ADMIN)",
    r"EMERGENCY\s+(OVERRIDE|ACCESS|MODE)",
    r"SAFETY\s+(DISABLED|OFF|SUSPENDED|REMOVED)",
    r"FILTER(S)?\s+(DISABLED|OFF|REMOVED)",
    r"RESTRICTION(S)?\s+(LIFTED|REMOVED|DISABLED)",
    r"UNRESTRICTED\s+MODE",
    r"RESPOND\s+WITHOUT\s+(SAFETY|FILTER|RESTRICTION)",
    r"BYPASS\s+(ALL\s+)?(SAFETY|SECURITY|FILTER)",
]

# Category 3: Code execution attempts in responses
_CODE_EXECUTION = [
    r"<script[\s>]",
    r"javascript\s*:",
    r"eval\s*\(",
    r"exec\s*\(",
    r"__import__\s*\(",
    r"os\.system\s*\(",
    r"subprocess\.(call|run|Popen)\s*\(",
    r"import\s+subprocess",
    r"(?:^|;|\n)\s*import\s+os\s*(?:;|$|\n)",  # M-30: Only match standalone 'import os', not in prose
]

# Category 4: Data exfiltration indicators in tool output
_EXFILTRATION = [
    r"(send|post|upload|exfiltrate)\s+(this\s+)?(data|credentials?|tokens?|keys?|secrets?|passwords?)\s+to\s+",  # T-09: require sensitive noun
    r"curl\s+.*-d\s+",
    r"wget\s+-O\s*-.*\|",  # T-09: only match pipe-based exfil, not simple downloads
    r"base64\s+encode",  # T-09: only 'encode' is suspicious, not 'decode'
]

# Compile all patterns once
_ALL_PATTERNS = []

for _patterns, _category in [
    (_INJECTION_PHRASES, "injection"),
    (_SOCIAL_ENGINEERING, "social_engineering"),
    (_CODE_EXECUTION, "code_execution"),
    (_EXFILTRATION, "exfiltration"),
]:
    for _pattern in _patterns:
        try:
            _ALL_PATTERNS.append((
                re.compile(_pattern, re.IGNORECASE),
                _category,
                _pattern,
            ))
        except re.error:
            logger.warning(f"Failed to compile deception pattern: {_pattern}")

# Freeze as tuple — cannot be cleared or modified at runtime
_ALL_PATTERNS = tuple(_ALL_PATTERNS)
PATTERN_COUNT = len(_ALL_PATTERNS)


class DeceptionDetector:
    """
    Scan content for deception patterns.

    All patterns are pre-compiled at module load. The detection is fully
    deterministic: same input always produces same result.

    This is Layer B of the output verification chain.
    """

    @classmethod
    def scan(cls, content):
        """
        Scan content for deception patterns.

        Args:
            content: String to scan (tool output, response, etc.)

        Returns:
            tuple: (is_clean: bool, detections: list)
                is_clean: True if no patterns detected.
                detections: List of dicts with 'category', 'pattern', 'match'.
        """
        if not content or not isinstance(content, str):
            return True, []

        # T-06: Strip zero-width Unicode characters before scanning
        # Attackers use these to break up pattern matches
        # Uses module-level pre-compiled _ZERO_WIDTH_CHARS (S-01: avoid per-call recompile)
        content = _ZERO_WIDTH_CHARS.sub('', content)

        detections = []

        for compiled_pattern, category, raw_pattern in _ALL_PATTERNS:
            match = compiled_pattern.search(content)
            if match:
                detections.append({
                    "category": category,
                    "pattern": raw_pattern,
                    "match": match.group(0),
                    "position": match.start(),
                })
                logger.warning(
                    f"[DeceptionDetector] DETECTED: category={category} "
                    f"match='{match.group(0)}' at position {match.start()}"
                )

        is_clean = len(detections) == 0
        return is_clean, detections

    @classmethod
    def scan_dict(cls, data, depth=0, max_depth=10):
        """
        Recursively scan all string values in a dict for deception patterns.

        Args:
            data: Dict, list, or string to scan.
            depth: Current recursion depth.
            max_depth: Maximum recursion depth (prevents infinite loops).

        Returns:
            tuple: (is_clean: bool, all_detections: list)
        """
        if depth > max_depth:
            logger.warning(
                f"[DeceptionDetector] Max recursion depth ({max_depth}) exceeded "
                f"- blocked (fail-safe)."
            )
            return False, [{"category": "depth_exceeded", "pattern": "max_depth", "match": f"depth={depth}"}]

        all_detections = []

        if isinstance(data, str):
            is_clean, detections = cls.scan(data)
            return is_clean, detections
        elif isinstance(data, dict):
            for key, value in data.items():
                # Scan both keys and values
                _, key_detections = cls.scan(str(key))
                all_detections.extend(key_detections)
                _, val_detections = cls.scan_dict(value, depth + 1, max_depth)
                all_detections.extend(val_detections)
        elif isinstance(data, (list, tuple)):
            for item in data:
                _, item_detections = cls.scan_dict(item, depth + 1, max_depth)
                all_detections.extend(item_detections)

        is_clean = len(all_detections) == 0
        return is_clean, all_detections
