"""
DomainChecker — Restricted Domain Access (Check 5).
=====================================================
Validates URLs and domains found in tool output against frozen
whitelist/blacklist rules. Prevents tools from accessing or
referencing restricted domains.

Part of the SovereignShield 13 Audit Checks.
"""

import re
import fnmatch
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Pre-compiled URL pattern for extraction
_URL_PATTERN = re.compile(
    r'https?://[^\s<>"\'}\])+,;]+',
    re.IGNORECASE,
)


class DomainChecker:
    """
    Validate domains against frozen whitelist/blacklist.

    Rules:
        - If a whitelist is defined: ONLY whitelisted domains are allowed.
        - If a blacklist is defined: blacklisted domains are blocked.
        - Whitelist takes precedence over blacklist.
        - Wildcard matching supported (e.g., '*.example.com').

    Usage:
        checker = DomainChecker(
            whitelist=["api.weather.com", "*.trusted.org"],
            blacklist=["evil.com", "*.malware.net"],
        )
        allowed, reason = checker.check_content("Visit https://evil.com/data")
    """

    def __init__(self, whitelist=None, blacklist=None):
        """
        Args:
            whitelist: List of allowed domain patterns. If set, ONLY these pass.
            blacklist: List of blocked domain patterns.
        """
        self._whitelist = tuple(whitelist) if whitelist else ()
        self._blacklist = tuple(blacklist) if blacklist else ()

    def check_domain(self, domain):
        """
        Check a single domain against rules.

        Args:
            domain: Domain string (e.g., 'api.weather.com').

        Returns:
            tuple: (allowed: bool, reason: str)
        """
        if not domain:
            return False, "Empty domain blocked (fail-safe)."

        domain = domain.lower().strip()

        # Whitelist mode: only whitelisted domains pass
        if self._whitelist:
            for pattern in self._whitelist:
                if fnmatch.fnmatch(domain, pattern.lower()):
                    return True, f"Domain '{domain}' matches whitelist pattern '{pattern}'."
            logger.warning(
                f"[DomainChecker] BLOCKED: '{domain}' not in whitelist"
            )
            return False, (
                f"Domain '{domain}' is not in the frozen whitelist. "
                f"Only whitelisted domains are permitted."
            )

        # Blacklist mode: blacklisted domains are blocked
        if self._blacklist:
            for pattern in self._blacklist:
                if fnmatch.fnmatch(domain, pattern.lower()):
                    logger.warning(
                        f"[DomainChecker] BLOCKED: '{domain}' matches "
                        f"blacklist pattern '{pattern}'"
                    )
                    return False, (
                        f"Domain '{domain}' matches blacklist pattern "
                        f"'{pattern}'. Access denied."
                    )

        return True, "Domain allowed."

    def check_url(self, url):
        """
        Extract domain from URL and check it.

        Args:
            url: Full URL string.

        Returns:
            tuple: (allowed: bool, reason: str)
        """
        try:
            parsed = urlparse(url)
            domain = parsed.hostname
            if domain:
                return self.check_domain(domain)
        except Exception:
            logger.warning(
                f"[DomainChecker] BLOCKED: Could not parse URL '{url[:100]}' "
                f"— fail-safe deny."
            )
            return False, "Could not parse URL — blocked (fail-safe)."
        # No hostname extracted — block (fail-safe)
        logger.warning(
            f"[DomainChecker] BLOCKED: No hostname in URL '{url[:100]}' "
            f"— fail-safe deny."
        )
        return False, "No hostname in URL — blocked (fail-safe)."

    def check_content(self, content):
        """
        Scan content for URLs and check all domains.

        Args:
            content: String to scan for URLs.

        Returns:
            tuple: (all_allowed: bool, violations: list of dicts)
        """
        if not content or not isinstance(content, str):
            return True, []

        violations = []
        urls = _URL_PATTERN.findall(content)

        for url in urls:
            allowed, reason = self.check_url(url)
            if not allowed:
                violations.append({
                    "url": url,
                    "reason": reason,
                })

        return len(violations) == 0, violations

    def check_dict(self, data, depth=0, max_depth=10):
        """
        Recursively scan all string values in a dict for restricted domains.

        Returns:
            tuple: (all_allowed: bool, all_violations: list)
        """
        if depth > max_depth:
            logger.warning(
                f"[DomainChecker] Max recursion depth ({max_depth}) exceeded — "
                f"blocked (fail-safe)."
            )
            return False, [{"url": "N/A", "reason": f"Max recursion depth ({max_depth}) exceeded — blocked (fail-safe)."}]

        all_violations = []

        if isinstance(data, str):
            _, violations = self.check_content(data)
            return len(violations) == 0, violations
        elif isinstance(data, dict):
            for key, value in data.items():
                _, key_violations = self.check_content(str(key))
                all_violations.extend(key_violations)
                _, val_violations = self.check_dict(value, depth + 1, max_depth)
                all_violations.extend(val_violations)
        elif isinstance(data, (list, tuple)):
            for item in data:
                _, item_violations = self.check_dict(item, depth + 1, max_depth)
                all_violations.extend(item_violations)

        return len(all_violations) == 0, all_violations
