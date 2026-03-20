"""
AuditLog — Hash-Chained Tamper-Evident Logging.
=================================================
Every verification decision, every incident, and every tool call
is logged with a hash chain for tamper detection.

Each entry includes the SHA-256 hash of the previous entry.
Tampering with any entry breaks the chain.

Part of Phase 7: Incident Response Pipeline.
"""

import hashlib
import hmac
import json
import time
import uuid
import os
import threading
import logging

logger = logging.getLogger(__name__)


class AuditLog:
    """
    Append-only, hash-chained audit log.

    Each entry is chained to the previous via SHA-256 hash.
    The log can be verified for tampering at any time.
    Thread-safe via lock.
    """

    def __init__(self, log_file=None):
        """
        Args:
            log_file: Optional file path for persistent storage.
                      If None, log is in-memory only.
        """
        self._entries = []
        self._last_hash = "0" * 64  # Genesis hash
        self._lock = threading.Lock()
        self._log_file = log_file

        if log_file:
            os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)

    def log_incident(self, tool_name, layer, severity, reason,
                     tool_output=None, input_params=None):
        """
        Log a verification incident.

        Args:
            tool_name: Name of the tool involved.
            layer: Which verification layer caught it.
            severity: CRITICAL, HIGH, MEDIUM, or LOW.
            reason: Human-readable reason for the incident.
            tool_output: Optional captured tool output.
            input_params: Optional captured input parameters.

        Returns:
            str: Unique incident ID (UUID).
        """
        incident_id = str(uuid.uuid4())
        now = time.time()
        entry = {
            "incident_id": incident_id,
            "timestamp": now,
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "tool_name": tool_name,
            "layer": layer,
            "severity": severity,
            "reason": reason,
            "type": "incident",
        }

        if tool_output is not None:
            # Truncate before serialization to avoid invalid JSON from mid-string cuts
            output_str = json.dumps(tool_output, default=str)
            if len(output_str) > 10000:
                entry["tool_output"] = output_str[:9990] + '..."'
                entry["tool_output_truncated"] = True
            else:
                entry["tool_output"] = output_str

        if input_params is not None:
            params_str = json.dumps(input_params, default=str)
            if len(params_str) > 5000:
                entry["input_params"] = params_str[:4990] + '..."'
                entry["input_params_truncated"] = True
            else:
                entry["input_params"] = params_str

        self._append(entry)
        return incident_id

    def log_verification(self, tool_name, accepted, layer, latency_ms, reason=""):
        """
        Log a verification result (both accepts and declines).

        Args:
            tool_name: Tool name.
            accepted: Whether the verification passed.
            layer: Final layer reached.
            latency_ms: Total verification latency.
            reason: Optional reason string.
        """
        now = time.time()
        entry = {
            "timestamp": now,
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "tool_name": tool_name,
            "accepted": accepted,
            "layer": layer,
            "latency_ms": round(latency_ms, 1),
            "reason": reason,
            "type": "verification",
        }
        self._append(entry)

    def _append(self, entry):
        """Append an entry with hash chaining. Thread-safe."""
        with self._lock:
            # Add hash chain
            entry["previous_hash"] = self._last_hash
            entry_json = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            entry["entry_hash"] = hashlib.sha256(entry_json.encode("utf-8")).hexdigest()

            self._entries.append(entry)
            self._last_hash = entry["entry_hash"]

            # Persist if log file configured
            # IMPORTANT: Re-serialize WITH entry_hash included so the file
            # is independently verifiable without the in-memory state.
            if self._log_file:
                try:
                    full_entry_json = json.dumps(entry, sort_keys=True, separators=(",", ":"))
                    with open(self._log_file, "a", encoding="utf-8") as f:
                        # M-05: File-level locking for multi-process safety
                        try:
                            import sys
                            if sys.platform == "win32":
                                import msvcrt
                                msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
                            else:
                                import fcntl
                                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                        except (ImportError, OSError):
                            pass  # Best-effort locking
                        f.write(full_entry_json + "\n")
                        f.flush()
                except Exception as e:
                    # M-06: Rollback in-memory state on write failure
                    self._entries.pop()
                    self._last_hash = entry["previous_hash"]
                    logger.error(f"[AuditLog] Failed to persist entry (in-memory rolled back): {e}")

    def verify_chain(self):
        """
        Verify the integrity of the entire hash chain.

        Returns:
            tuple: (is_valid: bool, broken_at: int or None)
        """
        if not self._entries:
            return True, None

        expected_prev = "0" * 64  # Genesis hash

        for i, entry in enumerate(self._entries):
            # Check previous hash link (constant-time comparison)
            if not hmac.compare_digest(entry.get("previous_hash", ""), expected_prev):
                return False, i

            # Verify entry hash
            entry_copy = dict(entry)
            stored_hash = entry_copy.pop("entry_hash", None)
            entry_json = json.dumps(entry_copy, sort_keys=True, separators=(",", ":"))
            computed_hash = hashlib.sha256(entry_json.encode("utf-8")).hexdigest()

            if not hmac.compare_digest(computed_hash, stored_hash or ""):
                return False, i

            expected_prev = stored_hash

        return True, None

    def get_incidents(self, severity=None, tool_name=None, limit=100):
        """
        Query incidents with optional filters.

        Args:
            severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW).
            tool_name: Filter by tool name.
            limit: Max results to return.

        Returns:
            List of incident entries (most recent first).
        """
        results = []
        for entry in reversed(self._entries):
            if entry.get("type") != "incident":
                continue
            if severity and entry.get("severity") != severity:
                continue
            if tool_name and entry.get("tool_name") != tool_name:
                continue
            results.append(dict(entry))  # Return copy to protect hash chain
            if len(results) >= limit:
                break
        return results

    @property
    def entry_count(self):
        return len(self._entries)

    @property
    def last_hash(self):
        return self._last_hash
