"""Regenerate the integrity lockfile by loading integrity_lock.py directly."""
import importlib.util, os, sys

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "integrity_lock",
    os.path.join(here, "sovereign_mcp", "integrity_lock.py")
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

data = mod.generate_lockfile()
print(f"Lockfile regenerated: {mod._LOCKFILE}")
print(f"  Files sealed: {data['file_count']}")
print(f"  Aggregate hash: {data['aggregate_hash']}")
