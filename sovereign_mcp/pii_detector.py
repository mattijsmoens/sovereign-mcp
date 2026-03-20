"""
PII Detector — Sensitive Data Detection in Tool Output.
=========================================================
Scans tool output for personally identifiable information (PII)
and sensitive data patterns before admitting it to the LLM context.

Part of the SovereignShield 13 Audit Checks (Check 4: PII/Sensitive Data).

Patterns detected:
    - Social Security Numbers (SSN)
    - Credit card numbers (pattern-matched, no Luhn validation)
    - Email addresses
    - Phone numbers (international formats)
    - IP addresses (IPv4)
    - API keys / tokens (common formats)
    - Passwords in key-value pairs
    - AWS access keys
    - Private keys (PEM format markers)

All patterns are pre-compiled at module load for performance.
Detection is fully deterministic: same input always produces same result.
"""

import re
import logging

logger = logging.getLogger(__name__)


# ===================================================================
# PRE-COMPILED PII PATTERNS
# Compiled once at module load. Cannot be modified at runtime.
# ===================================================================


_PATTERN_DEFINITIONS = [
    # Social Security Numbers (US)
    ("ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
    ("ssn_no_dash", r"(?i)(?:ssn|social\s*security)\s*[:=]?\s*\b\d{9}\b"),  # Requires SSN context

    # Credit card numbers (major formats)
    ("credit_card_visa", r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
    ("credit_card_mc", r"\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
    ("credit_card_amex", r"\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b"),

    # Email addresses
    ("email", r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),

    # Phone numbers (international)
    ("phone_us", r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    ("phone_intl", r"\b\+\d{1,3}[-.\s]?\d{4,14}\b"),

    # IP addresses (IPv4)
    ("ipv4", r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),

    # API keys / tokens (generic patterns)
    ("api_key_generic", r"\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?"),
    ("bearer_token", r"\bBearer\s+[a-zA-Z0-9_\-\.]{20,}\b"),

    # AWS access keys
    ("aws_access_key", r"\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b"),
    ("aws_secret_key", r"(?i)(?:aws_secret|secret_access_key|aws_secret_access_key)\s*[:=]\s*['\"]?[a-zA-Z0-9/+]{40}['\"]?"),  # Requires AWS context

    # Password patterns (key-value)
    ("password_field", r"(?i)\b(?:password|passwd|pwd|pass)\s*[:=]\s*\S+"),

    # Private key markers
    ("private_key_pem", r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
    ("private_key_ec", r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----"),

    # Database connection strings
    ("db_connection", r"(?i)(?:mongodb|postgres|mysql|redis)://[^\s]+"),

    # JWT tokens
    ("jwt_token", r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
]

# S-02: Build directly as tuple to eliminate mutable window during module load
def _compile_pii_patterns():
    """Compile all PII patterns and return as immutable tuple."""
    compiled = []
    for _name, _pattern in _PATTERN_DEFINITIONS:
        try:
            compiled.append((re.compile(_pattern), _name, _pattern))
        except re.error as e:
            logger.warning(f"Failed to compile PII pattern '{_name}': {e}")
    return tuple(compiled)


_PII_PATTERNS = _compile_pii_patterns()
del _compile_pii_patterns  # Remove factory function from module namespace

PII_PATTERN_COUNT = len(_PII_PATTERNS)


class PIIDetector:
    """
    Scan content for PII and sensitive data patterns.

    All patterns are pre-compiled at module load. Detection is fully
    deterministic: same input always produces same result.

    Part of the SovereignShield 13 Audit Checks.
    """

    # High-sensitivity patterns that should always be flagged
    HIGH_SENSITIVITY = {
        "ssn", "credit_card_visa", "credit_card_mc", "credit_card_amex",
        "private_key_pem", "private_key_ec", "aws_access_key",
        "password_field", "db_connection",
    }

    @classmethod
    def scan(cls, content):
        """
        Scan a string for PII patterns.

        Args:
            content: String to scan.

        Returns:
            tuple: (is_clean: bool, detections: list)
                is_clean: True if no PII patterns detected.
                detections: List of dicts with 'type', 'pattern_name',
                           'match' (redacted), 'position', 'sensitivity'.
        """
        if not content or not isinstance(content, str):
            return True, []

        detections = []

        for compiled_pattern, name, raw_pattern in _PII_PATTERNS:
            for match in compiled_pattern.finditer(content):
                matched_text = match.group(0)
                # Redact the match for logging (show first 4 and last 2 chars)
                if len(matched_text) > 8:
                    redacted = matched_text[:4] + "***" + matched_text[-2:]
                else:
                    redacted = "***"

                sensitivity = "HIGH" if name in cls.HIGH_SENSITIVITY else "MEDIUM"

                detections.append({
                    "type": name,
                    "match_redacted": redacted,
                    "position": match.start(),
                    "length": len(matched_text),
                    "sensitivity": sensitivity,
                })
                logger.warning(
                    f"[PIIDetector] DETECTED: type={name} "
                    f"sensitivity={sensitivity} "
                    f"match={redacted} at position {match.start()}"
                )

        is_clean = len(detections) == 0
        return is_clean, detections

    @classmethod
    def scan_dict(cls, data, depth=0, max_depth=10):
        """
        Recursively scan all string values in a dict for PII patterns.

        Args:
            data: Dict, list, or string to scan.
            depth: Current recursion depth.
            max_depth: Maximum recursion depth.

        Returns:
            tuple: (is_clean: bool, all_detections: list)
        """
        if depth > max_depth:
            return False, [{"type": "depth_exceeded", "sensitivity": "HIGH"}]

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
