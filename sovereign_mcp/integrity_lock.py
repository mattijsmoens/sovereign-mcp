"""
IntegrityLock — Source Code Self-Verification on Startup.
==========================================================
Hashes every .py source file in the sovereign_mcp package on first run
and saves the hashes to a lockfile. On every subsequent import, all
source files are re-hashed and compared against the lockfile.

If ANY source file has been modified, added, or deleted since the
lockfile was generated: the module raises IntegrityViolation and
REFUSES TO LOAD. The entire package becomes non-functional.

This prevents:
    - Post-install code tampering (supply chain attacks)
    - Runtime source modification (code injection)
    - Selective file replacement (partial compromise)

Usage:
    The integrity check runs automatically on `import sovereign_mcp`.
    To regenerate the lockfile after a legitimate update:
        python -m sovereign_mcp.integrity_lock --generate

Patent: Sovereign Shield Patent 3 (Immutable Runtime Constraints)
"""

import hashlib
import hmac
import json
import os
import sys
import logging

logger = logging.getLogger(__name__)

# The lockfile lives alongside the source files
_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_LOCKFILE = os.path.join(_PACKAGE_DIR, ".integrity_lock.json")


class IntegrityViolation(Exception):
    """Raised when source code tampering is detected."""
    pass


def _hash_file(filepath):
    """Compute SHA-256 hash of a file's contents."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


#: Compiled accelerators are OPTIONAL by design - the package ships
#: `frozen_memory_fallback.py` and runs on ctypes when no extension is built.
#: So their presence or absence is a supported configuration, not tampering:
#:
#:   * absent but in the lockfile  -> fine (a clean checkout, or a pure-Python
#:     install; this is what a fresh `git clone` looks like)
#:   * present but not in the lockfile -> fine (built locally after sealing)
#:   * present AND in the lockfile -> the hash must match, or it is tampering
#:
#: They are also excluded from the aggregate hash, which would otherwise differ
#: between a machine that compiled the extension and one that did not. Treating
#: an optional artifact as mandatory is what made the 1.3.1 and 1.3.2 wheels
#: unimportable, and it broke a fresh clone of this repository too.
_OPTIONAL_BINARY_SUFFIXES = (".pyd", ".so")


def _is_optional_binary(filename):
    return filename.endswith(_OPTIONAL_BINARY_SUFFIXES)


def _walk_package(suffixes):
    """Yield (relative_name, absolute_path) for package files, recursively.

    Recursive since 1.5.0. It was a flat listdir while the package was flat,
    but that silently left every subpackage outside the seal - including
    `integrations/`, which is the gate itself for MCP SDK users. A whole-package
    integrity check that skips a subpackage is not a whole-package check.

    Names are POSIX-relative to the package root so a lockfile generated on
    Windows verifies on Linux.
    """
    files = []
    for dirpath, dirnames, filenames in os.walk(_PACKAGE_DIR):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for entry in sorted(filenames):
            if not entry.endswith(suffixes):
                continue
            filepath = os.path.join(dirpath, entry)
            if not os.path.isfile(filepath):
                continue
            rel = os.path.relpath(filepath, _PACKAGE_DIR).replace(os.sep, "/")
            files.append((rel, filepath))
    return sorted(files)


def _get_source_files():
    """
    Get all .py source files in the package, recursively.
    Returns sorted list of (relative_name, absolute_path) tuples.
    Excludes the lockfile itself and __pycache__.
    """
    return _walk_package((".py",))


def _get_all_source_files():
    """
    Get all source files including .c extension and compiled binary files.
    Returns sorted list of (filename, absolute_path) tuples.
    L-14: Also includes .pyd (Windows) and .so (Unix) compiled extensions
    to detect supply-chain tampering of compiled binaries.
    """
    return _walk_package((".py", ".c", ".pyd", ".so"))


def generate_lockfile():
    """
    Generate the integrity lockfile by hashing all source files.

    This should be run ONCE after installation or after a legitimate
    code update. The lockfile is then used for verification on every
    subsequent import.

    Returns:
        dict: The generated lock data.
    """
    source_files = _get_all_source_files()
    lock_data = {
        "version": "1.0",
        "generator": "sovereign_mcp.integrity_lock",
        "file_count": len(source_files),
        "files": {},
    }

    for filename, filepath in source_files:
        # Skip the lockfile module itself from being locked
        # (it would change when the lockfile is written)
        file_hash = _hash_file(filepath)
        lock_data["files"][filename] = {
            "sha256": file_hash,
            "size": os.path.getsize(filepath),
        }

    # Compute aggregate hash over all individual hashes (sorted by filename).
    # Optional compiled accelerators are excluded so the aggregate is identical
    # on a machine that built the extension and one that did not; they are
    # still sealed individually and checked whenever they are present.
    aggregate_parts = []
    for filename in sorted(lock_data["files"].keys()):
        if _is_optional_binary(filename):
            continue
        aggregate_parts.append(f"{filename}:{lock_data['files'][filename]['sha256']}")
    aggregate_str = "|".join(aggregate_parts)
    lock_data["aggregate_hash"] = hashlib.sha256(
        aggregate_str.encode("utf-8")
    ).hexdigest()

    # Write lockfile
    with open(_LOCKFILE, "w", encoding="utf-8") as f:
        json.dump(lock_data, f, indent=2, sort_keys=True)

    logger.info(
        f"[IntegrityLock] Lockfile generated. {len(source_files)} files sealed. "
        f"Aggregate: {lock_data['aggregate_hash'][:16]}..."
    )
    return lock_data


def verify_integrity(strict=True):
    """
    Verify all source files against the lockfile.

    Args:
        strict: If True (default), raise IntegrityViolation on any
                mismatch. If False, return the result without raising.

    Returns:
        tuple: (is_valid: bool, violations: list of str)

    Raises:
        IntegrityViolation: If strict=True and any file has been tampered with.
    """
    violations = []

    # Check lockfile exists
    if not os.path.exists(_LOCKFILE):
        msg = (
            "INTEGRITY LOCKFILE NOT FOUND. "
            "Run `python -m sovereign_mcp.integrity_lock --generate` "
            "to create it after installation."
        )
        if strict:
            raise IntegrityViolation(
                f"\n{'='*60}\n"
                f"SOVEREIGN MCP — INTEGRITY VIOLATION\n"
                f"{'='*60}\n"
                f"{msg}\n"
                f"{'='*60}"
            )
        return False, [msg]

    # Load lockfile
    try:
        with open(_LOCKFILE, "r", encoding="utf-8") as f:
            lock_data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        msg = f"INTEGRITY LOCKFILE CORRUPTED: {e}"
        violations.append(msg)
        if strict:
            raise IntegrityViolation(msg)
        return False, violations

    locked_files = lock_data.get("files", {})
    current_files = _get_all_source_files()
    current_filenames = {name for name, _ in current_files}
    locked_filenames = set(locked_files.keys())

    # Check for deleted files (files in lockfile but not on disk).
    # An absent optional accelerator is a supported configuration, not a
    # deletion - see _OPTIONAL_BINARY_SUFFIXES.
    for missing in sorted(locked_filenames - current_filenames):
        if _is_optional_binary(missing):
            continue
        violations.append(
            f"FILE DELETED: '{missing}' exists in lockfile but not on disk. "
            f"Expected hash: {locked_files[missing]['sha256'][:16]}..."
        )

    # Check for added files (files on disk but not in lockfile).
    # A locally compiled accelerator is likewise expected.
    for added in sorted(current_filenames - locked_filenames):
        if _is_optional_binary(added):
            continue
        violations.append(
            f"FILE ADDED: '{added}' exists on disk but not in lockfile. "
            f"Unauthorized addition detected."
        )

    # Check each locked file for modifications
    # Store computed hashes to avoid re-hashing for aggregate check
    computed_hashes = {}
    for filename, filepath in current_files:
        if filename not in locked_files:
            continue  # Already reported as ADDED above

        expected = locked_files[filename]
        actual_hash = _hash_file(filepath)
        computed_hashes[filename] = actual_hash
        actual_size = os.path.getsize(filepath)

        if not hmac.compare_digest(actual_hash, expected["sha256"]):
            violations.append(
                f"FILE MODIFIED: '{filename}' hash mismatch. "
                f"Expected: {expected['sha256'][:16]}... "
                f"Got: {actual_hash[:16]}..."
            )
        elif actual_size != expected.get("size", actual_size):
            violations.append(
                f"FILE SIZE CHANGED: '{filename}' size mismatch. "
                f"Expected: {expected['size']} bytes, Got: {actual_size} bytes"
            )

    # Verify aggregate hash (reuse computed hashes — no re-hashing)
    if not violations:
        aggregate_parts = []
        for filename in sorted(locked_files.keys()):
            if _is_optional_binary(filename):
                continue          # excluded at generation time too
            if filename in computed_hashes:
                aggregate_parts.append(f"{filename}:{computed_hashes[filename]}")
        aggregate_str = "|".join(aggregate_parts)
        computed_aggregate = hashlib.sha256(
            aggregate_str.encode("utf-8")
        ).hexdigest()
        expected_aggregate = lock_data.get("aggregate_hash", "")

        if not hmac.compare_digest(computed_aggregate, expected_aggregate):
            violations.append(
                f"AGGREGATE HASH MISMATCH. "
                f"Expected: {expected_aggregate[:16]}... "
                f"Got: {computed_aggregate[:16]}..."
            )

    if violations:
        logger.critical(
            f"[IntegrityLock] SOURCE CODE TAMPERING DETECTED! "
            f"{len(violations)} violation(s) found."
        )
        for v in violations:
            logger.critical(f"[IntegrityLock]   → {v}")

        if strict:
            violation_text = "\n".join(f"  → {v}" for v in violations)
            raise IntegrityViolation(
                f"\n{'='*60}\n"
                f"SOVEREIGN MCP — INTEGRITY VIOLATION\n"
                f"{'='*60}\n"
                f"Source code tampering detected.\n"
                f"{len(violations)} violation(s):\n"
                f"{violation_text}\n"
                f"{'='*60}\n"
                f"The package REFUSES TO LOAD.\n"
                f"If this is a legitimate update, regenerate the lockfile:\n"
                f"  python -m sovereign_mcp.integrity_lock --generate\n"
                f"{'='*60}"
            )
    else:
        logger.info(
            f"[IntegrityLock] VERIFIED. All {len(locked_files)} source files "
            f"match lockfile. Aggregate: {lock_data.get('aggregate_hash', 'N/A')[:16]}..."
        )

    return len(violations) == 0, violations


# ================================================================
# CLI: python -m sovereign_mcp.integrity_lock --generate | --verify
# ================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # Windows consoles default to cp1252 and cannot encode the status glyphs
    # below, which would turn a successful run into a UnicodeEncodeError.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    if len(sys.argv) > 1 and sys.argv[1] == "--generate":
        print("Generating integrity lockfile...")
        data = generate_lockfile()
        print(f"✓ Lockfile generated: {_LOCKFILE}")
        print(f"  Files sealed: {data['file_count']}")
        print(f"  Aggregate hash: {data['aggregate_hash']}")
    elif len(sys.argv) > 1 and sys.argv[1] == "--verify":
        print("Verifying source code integrity...")
        try:
            is_valid, violations = verify_integrity(strict=False)
            if is_valid:
                print("✓ All source files verified. No tampering detected.")
            else:
                print(f"✗ TAMPERING DETECTED! {len(violations)} violations:")
                for v in violations:
                    print(f"  → {v}")
                sys.exit(1)
        except IntegrityViolation as e:
            print(str(e))
            sys.exit(1)
    else:
        print("Usage:")
        print("  python -m sovereign_mcp.integrity_lock --generate")
        print("    Generate lockfile after installation or legitimate update")
        print()
        print("  python -m sovereign_mcp.integrity_lock --verify")
        print("    Verify source code integrity against lockfile")
