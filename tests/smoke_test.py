"""Quick smoke test for all sovereign_mcp imports."""
import sys
import os
sys.stdout.reconfigure(line_buffering=True)

# Add project root to path
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)

print("=== Smoke Test: Individual Imports ===", flush=True)

modules = [
    "sovereign_mcp.frozen_namespace",
    "sovereign_mcp.tool_registry",
    "sovereign_mcp.schema_validator",
    "sovereign_mcp.permission_checker",
    "sovereign_mcp.deception_detector",
    "sovereign_mcp.pii_detector",
    "sovereign_mcp.content_safety",
    "sovereign_mcp.domain_checker",
    "sovereign_mcp.identity_checker",
    "sovereign_mcp.input_sanitizer",
    "sovereign_mcp.canonical_json",
    "sovereign_mcp.consensus",
    "sovereign_mcp.consensus_cache",
    "sovereign_mcp.audit_log",
    "sovereign_mcp.value_constraints",
    "sovereign_mcp.human_approval",
    "sovereign_mcp.rate_limiter",
    "sovereign_mcp.sandbox_registry",
    "sovereign_mcp.incident_response",
    "sovereign_mcp.transport_security",
    "sovereign_mcp.tool_updater",
    "sovereign_mcp.integrity_lock",
    "sovereign_mcp.output_gate",
]

for mod_name in modules:
    try:
        __import__(mod_name)
        print(f"  OK: {mod_name}", flush=True)
    except Exception as e:
        print(f"  FAIL: {mod_name} -> {e}", flush=True)

print("\n=== Smoke Test: Package Import ===", flush=True)
try:
    import sovereign_mcp
    print(f"  Version: {sovereign_mcp.__version__}", flush=True)
    print(f"  Exports: {len(sovereign_mcp.__all__)}", flush=True)
    print(f"  OK", flush=True)
except Exception as e:
    print(f"  FAIL: {e}", flush=True)

print("\n=== DONE ===", flush=True)
