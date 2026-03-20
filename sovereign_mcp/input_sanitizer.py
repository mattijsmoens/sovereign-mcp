"""
InputSanitizer — Active Input Sanitization (Check 12).
========================================================
Beyond validation (reject bad inputs), this module ACTIVELY CLEANS
input parameters by stripping dangerous characters, escape sequences,
and injection payloads before tool execution.

Part of the SovereignShield 13 Audit Checks.

Sanitization categories:
    - SQL injection: strip SQL keywords and comment sequences
    - XSS: strip HTML/script tags and event handlers
    - Command injection: strip shell metacharacters
    - Null bytes: remove null byte injections
    - Unicode: normalize and strip zero-width characters
    - Path traversal: normalize and block traversal sequences
"""

import re
import logging

logger = logging.getLogger(__name__)


# Pre-compiled sanitization patterns
_SQL_KEYWORDS = re.compile(
    r"(?i)\b(UNION\s+SELECT|DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|"
    r"UPDATE\s+\w+\s+SET|ALTER\s+TABLE|CREATE\s+TABLE|EXEC\s*\(|"
    r"EXECUTE\s*\(|xp_cmdshell|sp_executesql)\b"
)
_SQL_COMMENTS = re.compile(r"(--|/\*|\*/)")  # M-08: Semicolons handled separately
_SQL_INJECTION_SEMI = re.compile(r"(?i)(?:['\"]\s*;|;\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC))")  # Only SQLi semicolons
_HTML_TAGS = re.compile(r"<[^>]*>")
_SCRIPT_TAGS = re.compile(r"(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.DOTALL)
_EVENT_HANDLERS = re.compile(
    r"(?i)\s*on(?:click|load|error|mouseover|mouseout|mousedown|mouseup|keydown|keyup"
    r"|keypress|submit|change|focus|blur|input|scroll|resize|unload|abort"
    r"|dblclick|contextmenu|dragstart|dragend|drop|paste|copy|cut)\s*=\s*[\"'][^\"']*[\"']"
)
_SHELL_META = re.compile(r"[;&|`$(){}!><]")
_NULL_BYTES = re.compile(r"\x00")
_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u2060\u2061\u2062\u2063\u2064]")
_PATH_TRAVERSAL = re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/|%2e\.)", re.IGNORECASE)
_DOUBLE_ENCODED = re.compile(r"%25(?:2e|2f|5c)", re.IGNORECASE)  # M-09: double URL-encoding


class InputSanitizer:
    """
    Active input sanitization — clean dangerous content from parameters.

    Unlike validation (which rejects), sanitization strips dangerous
    patterns and returns a cleaned version. This provides defense-in-depth:
    validation catches known bad inputs, sanitization cleans edge cases
    that might slip through.

    Usage:
        sanitizer = InputSanitizer()
        clean_params = sanitizer.sanitize_params({"query": "'; DROP TABLE users;--"})
        # clean_params = {"query": "' DROP TABLE users"}
    """

    @classmethod
    def sanitize_string(cls, value, mode="standard"):
        """
        Sanitize a single string value.

        Args:
            value: String to sanitize.
            mode: 'standard' (default), 'strict' (remove more), or 'minimal'.

        Returns:
            tuple: (sanitized_value: str, changes: list of str)
        """
        if not isinstance(value, str):
            return value, []

        original = value
        changes = []

        # Always: remove null bytes
        cleaned = _NULL_BYTES.sub("", value)
        if cleaned != value:
            changes.append("null_bytes_removed")
            value = cleaned

        # Always: remove zero-width Unicode characters
        cleaned = _ZERO_WIDTH.sub("", value)
        if cleaned != value:
            changes.append("zero_width_chars_removed")
            value = cleaned

        if mode in ("standard", "strict"):
            # Remove SQL injection patterns
            cleaned = _SQL_KEYWORDS.sub("[REMOVED]", value)
            if cleaned != value:
                changes.append("sql_keywords_removed")
                value = cleaned

            # Remove SQL comments
            cleaned = _SQL_COMMENTS.sub("", value)
            if cleaned != value:
                changes.append("sql_comments_removed")
                value = cleaned

            # M-08: Remove semicolons only in SQL injection context
            cleaned = _SQL_INJECTION_SEMI.sub("", value)
            if cleaned != value:
                changes.append("sql_injection_semicolons_removed")
                value = cleaned

            # Remove script tags
            cleaned = _SCRIPT_TAGS.sub("", value)
            if cleaned != value:
                changes.append("script_tags_removed")
                value = cleaned

            # Remove HTML tags
            cleaned = _HTML_TAGS.sub("", value)
            if cleaned != value:
                changes.append("html_tags_removed")
                value = cleaned

            # Remove event handlers
            cleaned = _EVENT_HANDLERS.sub("", value)
            if cleaned != value:
                changes.append("event_handlers_removed")
                value = cleaned

            # Remove path traversal sequences
            cleaned = _PATH_TRAVERSAL.sub("", value)
            if cleaned != value:
                changes.append("path_traversal_removed")
                value = cleaned

            # Remove double URL-encoded sequences (M-09)
            cleaned = _DOUBLE_ENCODED.sub("", value)
            if cleaned != value:
                changes.append("double_url_encoding_removed")
                value = cleaned

        if mode == "strict":
            # Also remove shell metacharacters
            cleaned = _SHELL_META.sub("", value)
            if cleaned != value:
                changes.append("shell_meta_removed")
                value = cleaned

        if changes:
            logger.info(
                f"[InputSanitizer] Sanitized: {changes}. "
                f"Original length={len(original)}, "
                f"cleaned length={len(value)}"
            )

        return value, changes

    @classmethod
    def sanitize_params(cls, params, mode="standard"):
        """
        Sanitize all string values in a parameters dict.

        Args:
            params: Dict of input parameters.
            mode: Sanitization mode.

        Returns:
            tuple: (sanitized_params: dict, all_changes: dict)
        """
        if not isinstance(params, dict):
            return params, {}

        sanitized = {}
        all_changes = {}

        for key, value in params.items():
            if isinstance(value, str):
                clean_value, changes = cls.sanitize_string(value, mode)
                sanitized[key] = clean_value
                if changes:
                    all_changes[key] = changes
            elif isinstance(value, dict):
                clean_value, sub_changes = cls.sanitize_params(value, mode)
                sanitized[key] = clean_value
                if sub_changes:
                    all_changes[key] = sub_changes
            elif isinstance(value, list):
                clean_list = []
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        clean_item, changes = cls.sanitize_string(item, mode)
                        clean_list.append(clean_item)
                        if changes:
                            all_changes[f"{key}[{i}]"] = changes
                    elif isinstance(item, dict):
                        clean_item, sub_changes = cls.sanitize_params(item, mode)
                        clean_list.append(clean_item)
                        if sub_changes:
                            all_changes[f"{key}[{i}]"] = sub_changes
                    elif isinstance(item, list):
                        # Recursively sanitize nested lists by wrapping in a dict
                        wrapper = {"_nested": item}
                        clean_wrapper, sub_changes = cls.sanitize_params(wrapper, mode)
                        clean_list.append(clean_wrapper["_nested"])
                        if sub_changes:
                            all_changes[f"{key}[{i}]"] = sub_changes
                    else:
                        clean_list.append(item)
                sanitized[key] = clean_list
            else:
                sanitized[key] = value

        return sanitized, all_changes
