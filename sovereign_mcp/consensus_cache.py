"""
ConsensusCache — Cached Consensus Results for Performance.
==========================================================
Caches consensus verification results for identical inputs to avoid
redundant dual-model calls. Cache key is SHA-256 of (tool_name +
normalized input parameters). TTL is configurable per tool.

Part of Phase 9: Performance Optimization (Strategy A).

Security properties:
    - Cache is invalidated on tool update or security incident
    - Cache entries expire after configurable TTL
    - HIGH risk bypass is enforced by OutputGate, not this cache
    - Cache is thread-safe
"""

import hashlib
import json
import time
import threading
import logging

logger = logging.getLogger(__name__)


class ConsensusCacheEntry:
    """A single cached consensus result. Immutable after creation."""

    __slots__ = ("match", "hash_a", "hash_b", "reason", "created_at", "ttl", "tool_name", "_initialized")

    def __init__(self, match, hash_a, hash_b, reason, ttl, tool_name=""):
        object.__setattr__(self, 'match', match)
        object.__setattr__(self, 'hash_a', hash_a)
        object.__setattr__(self, 'hash_b', hash_b)
        object.__setattr__(self, 'reason', reason)
        object.__setattr__(self, 'created_at', time.time())
        object.__setattr__(self, 'ttl', ttl)
        object.__setattr__(self, 'tool_name', tool_name)
        object.__setattr__(self, '_initialized', True)

    def __setattr__(self, name, value):
        if getattr(self, '_initialized', False):
            raise AttributeError(
                f"ConsensusCacheEntry is immutable. Cannot set '{name}'."
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name):
        raise AttributeError(
            f"ConsensusCacheEntry is immutable. Cannot delete '{name}'."
        )

    @property
    def is_expired(self):
        return (time.time() - self.created_at) > self.ttl


class ConsensusCache:
    """
    Cache consensus verification results.

    Usage:
        cache = ConsensusCache(default_ttl=300)

        # Check cache before running consensus
        cached = cache.get("get_weather", {"city": "Brussels"})
        if cached:
            # Use cached result
        else:
            # Run full consensus, then cache
            cache.put("get_weather", {"city": "Brussels"}, result)
    """

    def __init__(self, default_ttl=300, max_entries=10000):
        """
        Args:
            default_ttl: Default time-to-live in seconds (5 minutes).
            max_entries: Maximum cache entries before eviction.
        """
        self._cache = {}  # cache_key -> ConsensusCacheEntry
        self._lock = threading.Lock()
        self._default_ttl = default_ttl
        self._max_entries = max_entries
        self._hits = 0
        self._misses = 0

    def _make_key(self, tool_name, input_params):
        """Generate cache key from tool name + normalized input."""
        try:
            canonical = json.dumps(
                {"tool": tool_name, "params": self._sort_recursive(input_params)},
                sort_keys=True, separators=(",", ":"),
                default=str,  # M-21: prevent crash on non-serializable params
            )
        except (TypeError, ValueError):
            # Fallback: use repr for completely non-serializable inputs
            canonical = repr({"tool": tool_name, "params": input_params})
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _sort_recursive(obj):
        """Recursively sort dict keys for consistent cache keys (M-25)."""
        if isinstance(obj, dict):
            return {k: ConsensusCache._sort_recursive(v) for k, v in sorted(obj.items())}
        elif isinstance(obj, (list, tuple)):
            return [ConsensusCache._sort_recursive(item) for item in obj]
        return obj

    def get(self, tool_name, input_params):
        """
        Look up a cached consensus result.

        Args:
            tool_name: Tool name.
            input_params: Input parameters dict.

        Returns:
            ConsensusCacheEntry or None if not cached/expired.
        """
        key = self._make_key(tool_name, input_params)

        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None

            if entry.is_expired:
                del self._cache[key]
                self._misses += 1
                logger.debug(
                    f"[ConsensusCache] EXPIRED: {tool_name} key={key[:12]}..."
                )
                return None

            self._hits += 1
            logger.debug(
                f"[ConsensusCache] HIT: {tool_name} key={key[:12]}... "
                f"age={time.time() - entry.created_at:.1f}s"
            )
            return entry

    def put(self, tool_name, input_params, consensus_result, ttl=None):
        """
        Cache a consensus result.

        Args:
            tool_name: Tool name.
            input_params: Input parameters dict.
            consensus_result: ConsensusResult from the verifier.
            ttl: Time-to-live in seconds (overrides default).
        """
        key = self._make_key(tool_name, input_params)
        entry_ttl = ttl if ttl is not None else self._default_ttl

        with self._lock:
            # Periodically clean expired entries (M-26)
            self._put_count = getattr(self, '_put_count', 0) + 1
            if self._put_count % 10 == 0:
                self._sweep_expired()

            # Evict oldest entries if at capacity
            if len(self._cache) >= self._max_entries:
                self._evict_oldest()

            self._cache[key] = ConsensusCacheEntry(
                match=consensus_result.match,
                hash_a=consensus_result.hash_a,
                hash_b=consensus_result.hash_b,
                reason=consensus_result.reason,
                ttl=entry_ttl,
                tool_name=tool_name,
            )
            logger.debug(
                f"[ConsensusCache] STORED: {tool_name} key={key[:12]}... "
                f"ttl={entry_ttl}s"
            )

    def invalidate(self, tool_name=None):
        """
        Invalidate cache entries.

        Args:
            tool_name: If provided, invalidate only entries for this tool.
                       If None, invalidate ALL entries.
        """
        with self._lock:
            if tool_name is None:
                count = len(self._cache)
                self._cache.clear()
                logger.info(
                    f"[ConsensusCache] INVALIDATED ALL: {count} entries cleared"
                )
            else:
                # Filter entries by stored tool_name
                keys_to_remove = [
                    k for k, v in self._cache.items()
                    if v.tool_name == tool_name
                ]
                for key in keys_to_remove:
                    del self._cache[key]
                logger.info(
                    f"[ConsensusCache] INVALIDATED (tool={tool_name}): "
                    f"{len(keys_to_remove)} entries cleared"
                )

    def _sweep_expired(self):
        """Remove all expired entries (M-26)."""
        now = time.time()
        expired_keys = [
            k for k, v in self._cache.items()
            if (now - v.created_at) > v.ttl
        ]
        for key in expired_keys:
            del self._cache[key]
        if expired_keys:
            logger.debug(f"[ConsensusCache] SWEEP: removed {len(expired_keys)} expired entries")

    def _evict_oldest(self):
        """Evict the oldest 10% of entries."""
        if not self._cache:
            return
        # Sort by creation time, remove oldest 10%
        entries = sorted(
            self._cache.items(),
            key=lambda kv: kv[1].created_at,
        )
        evict_count = max(1, len(entries) // 10)
        for key, _ in entries[:evict_count]:
            del self._cache[key]
        logger.debug(f"[ConsensusCache] EVICTED: {evict_count} oldest entries")

    @property
    def stats(self):
        """Cache statistics."""
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0
            return {
                "entries": len(self._cache),
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_pct": round(hit_rate, 1),
                "max_entries": self._max_entries,
                "default_ttl": self._default_ttl,
            }
