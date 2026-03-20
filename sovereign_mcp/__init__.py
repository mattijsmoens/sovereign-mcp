"""
Sovereign MCP — Deterministic MCP Security Architecture.

FrozenNamespace as Root of Trust for Model Context Protocol tool verification.

Usage:
    from sovereign_mcp import ToolRegistry, OutputGate

    registry = ToolRegistry()
    registry.register_tool(...)
    frozen = registry.freeze()

    gate = OutputGate(frozen)
    result = gate.verify(tool_name, tool_output)
"""

# ── Source Code Integrity Check ──────────────────────────────────
# MUST run BEFORE any other sovereign_mcp module is imported.
# integrity_lock.py only uses stdlib (hashlib, json, os, sys, logging),
# so it is safe to import first. If any source file has been tampered
# with since the lockfile was generated, the package REFUSES TO LOAD
# and no tampered module-level code ever executes.
import os as _os
if _os.environ.get("SOVEREIGN_MCP_SKIP_INTEGRITY") != "1":
    from sovereign_mcp.integrity_lock import verify_integrity, generate_lockfile, IntegrityViolation
    verify_integrity(strict=True)
else:
    from sovereign_mcp.integrity_lock import verify_integrity, generate_lockfile, IntegrityViolation

# ── Module Imports (integrity-verified) ──────────────────────────
# All imports below are safe: integrity_lock has already verified
# that every source file matches the sealed lockfile hashes.
from sovereign_mcp.frozen_namespace import FrozenNamespace, freeze_tool_definition, compute_hash
from sovereign_mcp.tool_registry import ToolRegistry, FrozenRegistry
from sovereign_mcp.schema_validator import SchemaValidator
from sovereign_mcp.permission_checker import PermissionChecker
from sovereign_mcp.deception_detector import DeceptionDetector
from sovereign_mcp.pii_detector import PIIDetector
from sovereign_mcp.content_safety import ContentSafety
from sovereign_mcp.domain_checker import DomainChecker
from sovereign_mcp.identity_checker import IdentityChecker
from sovereign_mcp.input_sanitizer import InputSanitizer
from sovereign_mcp.canonical_json import canonical_hash, canonical_dumps, normalize, hashes_match
from sovereign_mcp.consensus import ConsensusVerifier, ModelProvider, MockModelProvider
from sovereign_mcp.consensus_cache import ConsensusCache
from sovereign_mcp.output_gate import OutputGate, GateResult
from sovereign_mcp.audit_log import AuditLog
from sovereign_mcp.value_constraints import ValueConstraintChecker
from sovereign_mcp.human_approval import HumanApprovalChecker
from sovereign_mcp.rate_limiter import RateLimiter
from sovereign_mcp.sandbox_registry import SandboxRegistry
from sovereign_mcp.incident_response import IncidentResponder
from sovereign_mcp.transport_security import TransportSecurity
from sovereign_mcp.tool_updater import ToolUpdater, ToolUpdateAnalysis
from sovereign_mcp.input_filter import InputFilter, DEFAULT_BAD_SIGNALS, MULTILINGUAL_BAD_SIGNALS
from sovereign_mcp.adaptive_shield import AdaptiveShield, ATTACK_CATEGORIES
from sovereign_mcp.truth_guard import TruthGuard, DEFAULT_VERIFICATION_TOOLS
from sovereign_mcp.conscience import Conscience
from sovereign_mcp.siem_logger import SIEMLogger, Severity

__all__ = [
    # Core
    "FrozenNamespace", "freeze_tool_definition", "compute_hash",
    "ToolRegistry", "FrozenRegistry",
    # Layer A: Schema
    "SchemaValidator",
    # Layer B: Deception
    "DeceptionDetector",
    # PII (Check 4)
    "PIIDetector",
    # Content Safety (Check 10)
    "ContentSafety",
    # Domain Checker (Check 5)
    "DomainChecker",
    # Identity Checker (Check 9)
    "IdentityChecker",
    # Input Sanitizer (Check 12)
    "InputSanitizer",
    # Permission Checker (Check 7)
    "PermissionChecker",
    # Layer C: Consensus
    "canonical_hash", "canonical_dumps", "normalize", "hashes_match",
    "ConsensusVerifier", "ModelProvider", "MockModelProvider",
    "ConsensusCache",
    # Output Gate
    "OutputGate", "GateResult",
    # Audit & Incident Response
    "AuditLog",
    "IncidentResponder",
    # Countermeasures
    "ValueConstraintChecker", "HumanApprovalChecker",
    # Rate Limiter (Check 8)
    "RateLimiter",
    # Dynamic Tool Registration
    "SandboxRegistry",
    # Transport Security (mTLS)
    "TransportSecurity",
    # Safe Tool Update (Blue-Green)
    "ToolUpdater", "ToolUpdateAnalysis",
    # Integrity
    "verify_integrity", "generate_lockfile", "IntegrityViolation",
    # Input Filter (Multi-Decode Anti-Bypass)
    "InputFilter", "DEFAULT_BAD_SIGNALS", "MULTILINGUAL_BAD_SIGNALS",
    # Adaptive Shield (Self-Learning)
    "AdaptiveShield", "ATTACK_CATEGORIES",
    # Truth Guard (Hallucination Detection)
    "TruthGuard", "DEFAULT_VERIFICATION_TOOLS",
    # Conscience (Ethical Evaluation)
    "Conscience",
    # SIEM Logger (Enterprise Logging)
    "SIEMLogger", "Severity",
]
__version__ = "1.0.0"
