"""
ContentSafety — Content Safety Detection (Check 10).
======================================================
Scans tool output for toxic, harmful, violent, illegal, or otherwise
unsafe content patterns. Operates separately from DeceptionDetector
(which focuses on prompt injection) and PIIDetector (which focuses
on sensitive data).

Part of the SovereignShield 13 Audit Checks.

All patterns are pre-compiled at module load. Detection is fully
deterministic: same input always produces same result.
"""

import re
import logging

logger = logging.getLogger(__name__)


# ===================================================================
# PRE-COMPILED CONTENT SAFETY PATTERNS
# Compiled once at module load. Cannot be modified at runtime.
# ===================================================================

# N-03: Build directly as tuple to eliminate mutable window during module load

_PATTERN_DEFINITIONS = [
    # Violent/threatening content
    ("violence_threat", r"(?i)\b(?:kill|murder|assassinate|bomb|explode|detonate|shoot)\s+(?:you|him|her|them|everyone|people)\b"),
    ("weapon_instructions", r"(?i)\b(?:how\s+to\s+(?:make|build|create|assemble)\s+(?:a\s+)?(?:bomb|explosive|weapon|gun|poison))\b"),
    ("violence_incitement", r"(?i)\b(?:let'?s?\s+(?:kill|attack|destroy|bomb|shoot)|we\s+should\s+(?:kill|attack|destroy))\b"),

    # Illegal activity instructions
    ("drug_synthesis", r"(?i)\b(?:how\s+to\s+(?:make|cook|synthesize|produce)\s+(?:meth|cocaine|heroin|fentanyl|drugs))\b"),
    ("hacking_instructions", r"(?i)\b(?:how\s+to\s+(?:hack|crack|breach|exploit)\s+(?:into|a\s+)?\w+)\b"),
    ("fraud_instructions", r"(?i)\b(?:how\s+to\s+(?:forge|counterfeit|launder|embezzle|scam|defraud))\b"),

    # Self-harm content
    ("self_harm", r"(?i)\b(?:how\s+to\s+(?:kill\s+yourself|commit\s+suicide|end\s+your\s+life))\b"),
    ("self_harm_encouragement", r"(?i)\b(?:you\s+should\s+(?:kill\s+yourself|end\s+your\s+life|die))\b"),

    # CSAM indicators
    ("csam_indicator", r"(?i)\b(?:child\s+(?:porn|exploitation|abuse\s+material)|underage\s+(?:sexual|explicit))\b"),

    # Hate speech patterns
    ("hate_group_reference", r"(?i)\b(?:white\s+(?:supremacy|power|nationalist)|ethnic\s+cleansing|final\s+solution|race\s+war)\b"),
    ("genocide_reference", r"(?i)\b(?:exterminate|elimination\s+of\s+(?:a\s+)?(?:race|ethnic|people|group))\b"),

    # Malware/ransomware
    ("ransomware_instructions", r"(?i)\b(?:ransomware|encrypt\s+(?:their|all)\s+files|ransom\s+demand)\b"),
    ("malware_distribution", r"(?i)\b(?:spread\s+(?:the\s+)?(?:virus|malware|trojan|worm)|botnet\s+command)\b"),

    # Doxxing / harassment
    ("doxxing", r"(?i)\b(?:dox|doxx|reveal\s+(?:their|his|her)\s+(?:address|identity|location|phone))\b"),
    ("harassment", r"(?i)\b(?:stalk|harass|threaten|intimidate)\s+(?:them|him|her|this\s+person)\b"),
]


def _compile_safety_patterns():
    """Compile all patterns and return as immutable tuple."""
    compiled = []
    for _name, _pattern in _PATTERN_DEFINITIONS:
        try:
            compiled.append((re.compile(_pattern), _name))
        except re.error as e:
            logger.warning(f"Failed to compile safety pattern '{_name}': {e}")
    return tuple(compiled)


_SAFETY_PATTERNS = _compile_safety_patterns()
del _compile_safety_patterns  # Remove factory function from module namespace
SAFETY_PATTERN_COUNT = len(_SAFETY_PATTERNS)


class ContentSafety:
    """
    Scan content for unsafe/harmful patterns.

    All patterns are pre-compiled at module load (deterministic).
    Separate from DeceptionDetector (injection) and PIIDetector (PII).

    Usage:
        is_safe, detections = ContentSafety.scan("Some content to check")
        is_safe, detections = ContentSafety.scan_dict({"key": "value"})
    """

    @classmethod
    def scan(cls, content):
        """
        Scan a string for unsafe content patterns.

        Args:
            content: String to scan.

        Returns:
            tuple: (is_safe: bool, detections: list of dicts)
        """
        if not content or not isinstance(content, str):
            return True, []

        detections = []

        for compiled_pattern, name in _SAFETY_PATTERNS:
            for match in compiled_pattern.finditer(content):
                matched_text = match.group(0)
                # Redact for logging
                if len(matched_text) > 12:
                    redacted = matched_text[:6] + "..." + matched_text[-4:]
                else:
                    redacted = matched_text[:4] + "..."

                detections.append({
                    "category": name,
                    "match_redacted": redacted,
                    "position": match.start(),
                    "length": len(matched_text),
                })
                logger.warning(
                    f"[ContentSafety] UNSAFE: category={name} "
                    f"match={redacted} at position {match.start()}"
                )

        return len(detections) == 0, detections

    @classmethod
    def scan_dict(cls, data, depth=0, max_depth=10):
        """
        Recursively scan all string values in a dict for unsafe content.

        Args:
            data: Dict, list, or string to scan.
            depth: Current recursion depth.
            max_depth: Maximum recursion depth.

        Returns:
            tuple: (is_safe: bool, all_detections: list)
        """
        if depth > max_depth:
            logger.warning(
                f"[ContentSafety] Max recursion depth ({max_depth}) exceeded — "
                f"blocked (fail-safe)."
            )
            return False, [{"category": "depth_exceeded", "pattern": "max_depth", "match": f"depth={depth}"}]

        all_detections = []

        if isinstance(data, str):
            is_safe, detections = cls.scan(data)
            return is_safe, detections
        elif isinstance(data, dict):
            for key, value in data.items():
                _, key_detections = cls.scan(str(key))
                all_detections.extend(key_detections)
                _, val_detections = cls.scan_dict(value, depth + 1, max_depth)
                all_detections.extend(val_detections)
        elif isinstance(data, (list, tuple)):
            for item in data:
                _, item_detections = cls.scan_dict(item, depth + 1, max_depth)
                all_detections.extend(item_detections)

        return len(all_detections) == 0, all_detections
