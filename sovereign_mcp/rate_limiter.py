"""
RateLimiter — Per-Tool Rate Limiting (Frozen Thresholds).
==========================================================
Enforces frozen rate limits per tool. Prevents abuse even if all
verification layers pass. Limits are frozen in FrozenNamespace and
cannot be modified at runtime.

Part of the SovereignShield 13 Audit Checks (Check 8: Rate Limiting).
"""

import collections
import time
import threading
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Per-tool rate limiting with frozen thresholds.

    Tracks call counts per tool within sliding time windows.
    Limits are defined per tool at registration and frozen.

    Usage:
        limiter = RateLimiter()
        allowed, reason = limiter.check("send_money", max_per_minute=10)
    """

    def __init__(self):
        self._calls = {}  # tool_name -> list of timestamps
        self._lock = threading.Lock()

    def check(self, tool_name, max_per_minute=None, max_per_hour=None):
        """
        Check if a tool call is within rate limits.

        Args:
            tool_name: Name of the tool being called.
            max_per_minute: Maximum calls per minute (frozen limit).
            max_per_hour: Maximum calls per hour (frozen limit).

        Returns:
            tuple: (allowed: bool, reason: str)
        """
        if max_per_minute is None and max_per_hour is None:
            return True, "No rate limits defined."

        now = time.time()

        with self._lock:
            if tool_name not in self._calls:
                self._calls[tool_name] = collections.deque()

            calls = self._calls[tool_name]

            # Periodic cleanup: only prune when deque is large
            # Prune calls older than the longest window (1 hour)
            if len(calls) > 1000: # Heuristic to avoid pruning on every call
                cutoff = now - 3600 # 1 hour
                while calls and calls[0] < cutoff:
                    calls.popleft()

            # Check per-minute limit
            if max_per_minute is not None:
                calls_last_minute = sum(1 for t in calls if now - t < 60)
                if calls_last_minute >= max_per_minute:
                    logger.warning(
                        f"[RateLimiter] DECLINED: {tool_name} "
                        f"exceeded {max_per_minute}/min "
                        f"({calls_last_minute} calls in last 60s)"
                    )
                    return False, (
                        f"Rate limit exceeded: '{tool_name}' has made "
                        f"{calls_last_minute} calls in the last minute "
                        f"(limit: {max_per_minute}/min)."
                    )

            # Check per-hour limit
            if max_per_hour is not None:
                calls_last_hour = sum(1 for t in calls if now - t < 3600)
                if calls_last_hour >= max_per_hour:
                    logger.warning(
                        f"[RateLimiter] DECLINED: {tool_name} "
                        f"exceeded {max_per_hour}/hr "
                        f"({calls_last_hour} calls in last 60min)"
                    )
                    return False, (
                        f"Rate limit exceeded: '{tool_name}' has made "
                        f"{calls_last_hour} calls in the last hour "
                        f"(limit: {max_per_hour}/hr)."
                    )

            # Record this call
            calls.append(now)

        return True, "Within rate limits."

    def get_usage(self, tool_name):
        """Get current usage stats for a tool."""
        now = time.time()
        with self._lock:
            calls = self._calls.get(tool_name, [])
            last_minute = sum(1 for t in calls if now - t < 60)
            last_hour = sum(1 for t in calls if now - t < 3600)
            return {
                "calls_last_minute": last_minute,
                "calls_last_hour": last_hour,
            }

    def reset(self, tool_name=None):
        """Reset rate limit counters. If tool_name is None, reset all."""
        with self._lock:
            if tool_name:
                self._calls.pop(tool_name, None)
            else:
                self._calls.clear()
