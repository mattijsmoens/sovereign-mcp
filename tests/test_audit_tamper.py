"""
Audit log tamper-detection tests.

`verify_chain()` verified `self._entries` — the IN-MEMORY list — and `__init__`
never read the log file. So constructing an AuditLog over an existing log and
calling verify_chain() checked an empty list and returned (True, None) no
matter what the file contained. Editing an entry, deleting one, and truncating
the tail were all reported as an intact chain.

The same omission meant `_last_hash` reset to the genesis hash on restart, so
every entry written after a restart claimed previous_hash = 000...0 and
silently broke chain continuity.
"""

import json
import os

import pytest

from sovereign_mcp import AuditLog


@pytest.fixture
def log_path(tmp_path):
    return str(tmp_path / "audit.jsonl")


def _seed(path, count=5):
    log = AuditLog(log_file=path)
    for i in range(count):
        log.log_incident(tool_name=f"tool{i}", layer="layer_a_schema",
                         severity="LOW", reason=f"reason {i}")
    return log


def _lines(path):
    with open(path, encoding="utf-8") as f:
        return f.read().splitlines()


def _write(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


class TestIntactChain:

    def test_verifies(self, log_path):
        log = _seed(log_path)
        assert log.verify_chain() == (True, None)

    def test_fresh_instance_verifies_persisted_chain(self, log_path):
        _seed(log_path)
        assert AuditLog(log_file=log_path).verify_chain() == (True, None)

    def test_empty_log_is_not_a_break(self, log_path):
        assert AuditLog(log_file=log_path).verify_chain() == (True, None)


class TestTamperDetected:
    """Each of these previously returned (True, None)."""

    def test_edited_entry(self, log_path):
        _seed(log_path)
        lines = _lines(log_path)
        entry = json.loads(lines[2])
        entry["reason"] = "TAMPERED"
        lines[2] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        _write(log_path, lines)

        valid, broken_at = AuditLog(log_file=log_path).verify_chain()
        assert valid is False
        assert broken_at == 2

    def test_deleted_entry(self, log_path):
        _seed(log_path)
        lines = _lines(log_path)
        _write(log_path, [l for i, l in enumerate(lines) if i != 3])

        valid, _ = AuditLog(log_file=log_path).verify_chain()
        assert valid is False

    def test_truncated_tail(self, log_path):
        """A plain hash chain cannot catch this; the head anchor can."""
        _seed(log_path)
        _write(log_path, _lines(log_path)[:3])

        valid, _ = AuditLog(log_file=log_path).verify_chain()
        assert valid is False

    def test_corrupted_line(self, log_path):
        _seed(log_path)
        lines = _lines(log_path)
        lines[1] = "{not json"
        _write(log_path, lines)

        valid, _ = AuditLog(log_file=log_path).verify_chain()
        assert valid is False


class TestChainSurvivesRestart:

    def test_continuity_across_instances(self, log_path):
        _seed(log_path, count=3)
        reopened = AuditLog(log_file=log_path)
        reopened.log_incident(tool_name="after-restart", layer="layer_b_deception",
                              severity="MEDIUM", reason="new")
        assert reopened.verify_chain() == (True, None)
        assert len(_lines(log_path)) == 4

    def test_second_entry_links_to_the_first_run(self, log_path):
        _seed(log_path, count=2)
        first_head = json.loads(_lines(log_path)[-1])["entry_hash"]

        reopened = AuditLog(log_file=log_path)
        reopened.log_incident(tool_name="t", layer="l", severity="LOW", reason="r")

        new_entry = json.loads(_lines(log_path)[-1])
        assert new_entry["previous_hash"] == first_head, (
            "a restarted log must continue the chain, not restart from genesis"
        )


class TestInMemoryModeStillWorks:

    def test_no_file_configured(self):
        log = AuditLog()
        log.log_incident(tool_name="t", layer="l", severity="LOW", reason="r")
        assert log.verify_chain() == (True, None)
