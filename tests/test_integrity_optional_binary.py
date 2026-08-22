"""The compiled accelerator is optional, and the seal must know that.

`frozen_memory.<abi>.pyd` / `.so` is built locally when a compiler is present
and absent otherwise - the package ships `frozen_memory_fallback.py` and runs
on ctypes without it. Both states are supported configurations.

Treating that optional artifact as mandatory is what made the published 1.3.1
and 1.3.2 wheels unimportable, and it broke a fresh `git clone` of this
repository too: the lockfile was generated on a machine that had compiled the
extension, so every checkout without it failed the seal on import.

What must remain true, and what these tests pin:

  absent, but in the lockfile        -> allowed  (clean checkout)
  present, but not in the lockfile   -> allowed  (built after sealing)
  present and in the lockfile        -> hash must match, or it is tampering
  any .py missing, added or edited   -> always tampering
"""

import json

import pytest

from sovereign_mcp import integrity_lock


class TestOptionalBinaryClassification:

    @pytest.mark.parametrize("name", [
        "frozen_memory.cp312-win_amd64.pyd",
        "frozen_memory.cpython-311-x86_64-linux-gnu.so",
        "anything.pyd",
        "anything.so",
    ])
    def test_compiled_extensions_are_optional(self, name):
        assert integrity_lock._is_optional_binary(name) is True

    @pytest.mark.parametrize("name", [
        "output_gate.py",
        "integrations/mcp_sdk.py",
        "frozen_memory.c",
        "frozen_memory_fallback.py",
    ])
    def test_source_files_are_never_optional(self, name):
        # A .py going missing must always be a violation - that is the whole
        # point of the seal.
        assert integrity_lock._is_optional_binary(name) is False


class TestVerificationTolerance:
    """Drive verify_integrity against a doctored lockfile in memory."""

    @staticmethod
    def _lock_data():
        with open(integrity_lock._LOCKFILE, encoding="utf-8") as handle:
            return json.load(handle)

    def test_the_real_tree_verifies(self):
        valid, violations = integrity_lock.verify_integrity(strict=False)
        assert valid, violations

    def test_a_lockfile_entry_for_an_absent_extension_is_tolerated(self, tmp_path,
                                                                   monkeypatch):
        # Exactly the fresh-clone case: the lockfile names an extension this
        # machine never built.
        data = self._lock_data()
        data["files"]["frozen_memory.cpython-999-nonexistent.so"] = {
            "sha256": "0" * 64, "size": 1}
        lockfile = tmp_path / "lock.json"
        lockfile.write_text(json.dumps(data), encoding="utf-8")
        monkeypatch.setattr(integrity_lock, "_LOCKFILE", str(lockfile))

        valid, violations = integrity_lock.verify_integrity(strict=False)
        assert valid, violations

    def test_a_lockfile_entry_for_an_absent_source_file_is_a_violation(
            self, tmp_path, monkeypatch):
        data = self._lock_data()
        data["files"]["a_module_that_was_deleted.py"] = {
            "sha256": "0" * 64, "size": 1}
        lockfile = tmp_path / "lock.json"
        lockfile.write_text(json.dumps(data), encoding="utf-8")
        monkeypatch.setattr(integrity_lock, "_LOCKFILE", str(lockfile))

        valid, violations = integrity_lock.verify_integrity(strict=False)
        assert not valid
        assert any("DELETED" in v for v in violations), violations

    def test_a_present_extension_with_a_wrong_hash_is_a_violation(
            self, tmp_path, monkeypatch):
        # Tamper detection on the binary must survive making it optional.
        data = self._lock_data()
        # It must be present ON DISK, not merely named in the lockfile - a
        # lockfile entry for an absent extension is the tolerated case, and
        # checking the wrong one made this test pass only on a machine that
        # had compiled the extension.
        on_disk = {name for name, _ in integrity_lock._get_all_source_files()}
        present = [n for n in data["files"]
                   if integrity_lock._is_optional_binary(n) and n in on_disk]
        if not present:
            pytest.skip("no compiled extension built in this checkout")
        data["files"][present[0]]["sha256"] = "0" * 64
        lockfile = tmp_path / "lock.json"
        lockfile.write_text(json.dumps(data), encoding="utf-8")
        monkeypatch.setattr(integrity_lock, "_LOCKFILE", str(lockfile))

        valid, violations = integrity_lock.verify_integrity(strict=False)
        assert not valid
        assert any("MODIFIED" in v for v in violations), violations


class TestAggregateStability:

    def test_the_aggregate_ignores_optional_binaries(self):
        # The aggregate must be identical on a machine that compiled the
        # extension and one that did not, or half the world fails the seal.
        import hashlib

        with open(integrity_lock._LOCKFILE, encoding="utf-8") as handle:
            data = json.load(handle)

        def aggregate(files):
            parts = ["%s:%s" % (name, files[name]["sha256"])
                     for name in sorted(files)
                     if not integrity_lock._is_optional_binary(name)]
            return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

        with_binaries = dict(data["files"])
        without = {n: v for n, v in data["files"].items()
                   if not integrity_lock._is_optional_binary(n)}

        assert aggregate(with_binaries) == aggregate(without)
        assert aggregate(with_binaries) == data["aggregate_hash"]
