#!/usr/bin/env python3
"""
Verify a built sovereign-mcp wheel is internally consistent.

The package refuses to import if .integrity_lock.json disagrees with the files
on disk, so a wheel whose lockfile is out of step is completely unusable.
That is how 1.3.1 and 1.3.2 shipped.

The check must run in BOTH directions:
  * every shipped .py/.c must match its lockfile hash, AND
  * every lockfile entry must actually be shipped.

Checking only the first direction misses the "FILE DELETED" failure, where the
lockfile references a compiled artifact the portable wheel does not contain.

    python verify_dist.py dist/sovereign_mcp-*.whl
"""

import hashlib
import json
import sys
import zipfile

PREFIX = "sovereign_mcp/"


def verify(path):
    z = zipfile.ZipFile(path)
    try:
        lock = json.loads(z.read(PREFIX + ".integrity_lock.json"))
    except KeyError:
        print(f"FAIL {path}: no .integrity_lock.json in wheel")
        return False

    locked = lock.get("files", {})
    shipped = {n[len(PREFIX):]: n for n in z.namelist() if n.startswith(PREFIX)}
    problems = []

    # Direction 1: shipped files must match the lockfile.
    for rel, full in sorted(shipped.items()):
        if not rel.endswith((".py", ".c", ".pyd", ".so")):
            continue
        entry = locked.get(rel)
        if entry is None:
            problems.append(f"{rel}: shipped but NOT in lockfile")
            continue
        expected = entry.get("sha256") if isinstance(entry, dict) else entry
        actual = hashlib.sha256(z.read(full)).hexdigest()
        if actual != expected:
            problems.append(f"{rel}: hash mismatch")

    # Direction 2: every lockfile entry must be shipped.
    for rel in sorted(locked):
        if rel not in shipped:
            problems.append(f"{rel}: in lockfile but NOT shipped (import will "
                            f"fail with FILE DELETED)")

    name = path.split("/")[-1].split("\\")[-1]
    if problems:
        print(f"FAIL {name}: {len(problems)} problem(s)")
        for p in problems:
            print(f"   - {p}")
        return False
    print(f"OK   {name}: {len(locked)} lockfile entries, all shipped and matching")
    return True


if __name__ == "__main__":
    targets = sys.argv[1:]
    if not targets:
        print(__doc__)
        sys.exit(2)
    sys.exit(0 if all([verify(t) for t in targets]) else 1)
