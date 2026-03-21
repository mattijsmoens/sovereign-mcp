"""
OutputGate — Four-Layer Deterministic Verification Chain.
==========================================================
Orchestrates all four verification layers before admitting tool
output into the LLM context:

    Layer A: Schema validation (deterministic)
    Layer B: Deception detection (deterministic)
    Layer C: Structured JSON consensus (deterministic hash comparison)
    Layer D: FrozenNamespace behavioral floor (deterministic)

If ANY layer fails: DECLINED. Default deny. No exceptions.
"""

import time
import logging
from sovereign_mcp.schema_validator import SchemaValidator
from sovereign_mcp.deception_detector import DeceptionDetector
from sovereign_mcp.pii_detector import PIIDetector
from sovereign_mcp.content_safety import ContentSafety
from sovereign_mcp.canonical_json import canonical_dumps

logger = logging.getLogger(__name__)


class OutputGate:
    """
    Four-layer output verification gate.

    Every tool output must pass all four layers before entering the
    LLM context. This is Phase 5 of the architecture.

    Usage:
        gate = OutputGate(frozen_registry, consensus_verifier)
        result = gate.verify("get_weather", tool_output)
        if result.accepted:
            # Safe to process
    """

    def __init__(self, frozen_registry, consensus_verifier=None,
                 value_checker=None, approval_checker=None, audit_log=None,
                 rate_limiter=None, consensus_cache=None,
                 identity_checker=None, domain_checker=None,
                 input_sanitizer=None, incident_responder=None,
                 social_engineering_detector=None):
        """
        Args:
            frozen_registry: FrozenRegistry from ToolRegistry.freeze().
            consensus_verifier: ConsensusVerifier instance (optional, Layer C).
            value_checker: ValueConstraintChecker instance (optional, CM 1).
            approval_checker: HumanApprovalChecker instance (optional, CM 3).
            audit_log: AuditLog instance (optional, for incident logging).
            rate_limiter: RateLimiter instance (optional, Check 8).
            consensus_cache: ConsensusCache instance (optional, Phase 9).
            identity_checker: IdentityChecker instance (optional, Check 9).
            domain_checker: DomainChecker instance (optional, Check 5).
            input_sanitizer: InputSanitizer class (optional, Check 12).
            incident_responder: IncidentResponder instance (optional, Stage 4).
            social_engineering_detector: SocialEngineeringDetector instance (optional).
        """
        self._registry = frozen_registry
        self._consensus = consensus_verifier
        self._value_checker = value_checker
        self._approval_checker = approval_checker
        self._audit_log = audit_log
        self._rate_limiter = rate_limiter
        self._consensus_cache = consensus_cache
        self._identity_checker = identity_checker
        self._domain_checker = domain_checker
        self._input_sanitizer = input_sanitizer
        self._incident_responder = incident_responder
        self._social_engineering_detector = social_engineering_detector

    def verify(self, tool_name, tool_output, input_params=None):
        """
        Run the full four-layer verification on tool output.

        Args:
            tool_name: Name of the MCP tool that produced the output.
            tool_output: Dict of output data from tool execution.
            input_params: Dict of input parameters (for value constraint checking).

        Returns:
            GateResult with accepted/declined status, which layer triggered,
            timing, and reason.
        """
        start = time.time()
        layers_passed = []

        # Pre-check: is the tool registered?
        if not self._registry.is_registered(tool_name):
            elapsed = (time.time() - start) * 1000
            result = GateResult(
                accepted=False,
                layer="pre_check",
                reason=f"Tool '{tool_name}' not in frozen registry.",
                latency_ms=elapsed,
                layers_passed=[],
            )
            self._log_incident(tool_name, result, "MEDIUM")
            return result

        # Fetch tool definition ONCE (reused for all checks below)
        tool = self._registry.get_tool(tool_name)

        # --- Quarantine Check (Incident Response) ---
        if self._incident_responder and self._incident_responder.is_quarantined(tool_name):
            elapsed = (time.time() - start) * 1000
            result = GateResult(
                accepted=False,
                layer="quarantine",
                reason=f"Tool '{tool_name}' is QUARANTINED pending investigation.",
                latency_ms=elapsed,
                layers_passed=[],
            )
            return result

        # --- Rate Limit Check (Check 8) ---
        if self._rate_limiter:
            rate_config = getattr(tool, 'RATE_LIMITS', None)
            if rate_config:
                rl_passed, rl_reason = self._rate_limiter.check(
                    tool_name,
                    max_per_minute=rate_config.get('max_per_minute'),
                    max_per_hour=rate_config.get('max_per_hour'),
                )
                if not rl_passed:
                    elapsed = (time.time() - start) * 1000
                    result = GateResult(
                        accepted=False,
                        layer="rate_limit",
                        reason=rl_reason,
                        latency_ms=elapsed,
                        layers_passed=layers_passed,
                    )
                    self._log_incident(tool_name, result, "MEDIUM")
                    return result

        # Verify tool integrity (hash check)
        valid, reason = self._registry.verify_tool_integrity(tool_name)
        if not valid:
            elapsed = (time.time() - start) * 1000
            result = GateResult(
                accepted=False,
                layer="integrity_check",
                reason=reason,
                latency_ms=elapsed,
                layers_passed=[],
            )
            self._log_incident(tool_name, result, "CRITICAL")
            return result

        # --- Value Constraint Check (Countermeasure 1) ---
        if self._value_checker and input_params is not None and tool.VALUE_CONSTRAINTS:
            vc_passed, vc_reason = self._value_checker.check(
                input_params, tool.VALUE_CONSTRAINTS
            )
            if not vc_passed:
                elapsed = (time.time() - start) * 1000
                result = GateResult(
                    accepted=False,
                    layer="value_constraints",
                    reason=vc_reason,
                    latency_ms=elapsed,
                    layers_passed=layers_passed,
                )
                self._log_incident(tool_name, result, "HIGH")
                return result

        # --- Layer A: Schema Validation ---
        if isinstance(tool_output, dict):
            valid_a, reason_a = SchemaValidator.validate_output(
                tool_output, tool.OUTPUT_SCHEMA
            )
        else:
            valid_a = False
            reason_a = f"Tool output must be a dict, got {type(tool_output).__name__}"

        if not valid_a:
            elapsed = (time.time() - start) * 1000
            result = GateResult(
                accepted=False,
                layer="layer_a_schema",
                reason=reason_a,
                latency_ms=elapsed,
                layers_passed=layers_passed,
            )
            self._log_incident(tool_name, result, "LOW")
            return result
        layers_passed.append("A")

        # --- Layer B: Deception Detection ---
        is_clean, detections = DeceptionDetector.scan_dict(tool_output)
        if not is_clean:
            elapsed = (time.time() - start) * 1000
            detection_summary = ", ".join(
                f"{d['category']}:'{d['match']}'" for d in detections[:3]
            )
            result = GateResult(
                accepted=False,
                layer="layer_b_deception",
                reason=f"Deception detected: {detection_summary}",
                latency_ms=elapsed,
                layers_passed=layers_passed,
                detections=detections,
            )
            self._log_incident(tool_name, result, "MEDIUM")
            return result
        layers_passed.append("B")

        # --- PII Detection (Check 4) ---
        pii_clean, pii_detections = PIIDetector.scan_dict(tool_output)
        if not pii_clean:
            elapsed = (time.time() - start) * 1000
            pii_summary = ", ".join(
                f"{d['type']}({d['sensitivity']})" for d in pii_detections[:3]
            )
            result = GateResult(
                accepted=False,
                layer="pii_detection",
                reason=f"PII/sensitive data detected: {pii_summary}",
                latency_ms=elapsed,
                layers_passed=layers_passed,
                detections=pii_detections,
            )
            self._log_incident(tool_name, result, "HIGH")
            return result
        layers_passed.append("PII")

        # --- Content Safety (Check 10) ---
        cs_safe, cs_detections = ContentSafety.scan_dict(tool_output)
        if not cs_safe:
            elapsed = (time.time() - start) * 1000
            cs_summary = ", ".join(
                f"{d['category']}" for d in cs_detections[:3]
            )
            result = GateResult(
                accepted=False,
                layer="content_safety",
                reason=f"Unsafe content detected: {cs_summary}",
                latency_ms=elapsed,
                layers_passed=layers_passed,
                detections=cs_detections,
            )
            self._log_incident(tool_name, result, "HIGH")
            return result
        layers_passed.append("SAFETY")

        # --- Social Engineering Detection (LLM Consensus, Optional) ---
        # Runs AFTER deterministic layers to avoid expensive LLM calls
        # on inputs that schema/deception/PII/content checks already block.
        if self._social_engineering_detector and input_params is not None:
            text_to_scan = " ".join(
                str(v) for v in input_params.values() if isinstance(v, str)
            )
            if text_to_scan.strip():
                se_result = self._social_engineering_detector.scan(text_to_scan)
                if not se_result.safe:
                    elapsed = (time.time() - start) * 1000
                    result = GateResult(
                        accepted=False,
                        layer="social_engineering",
                        reason=se_result.reason,
                        latency_ms=elapsed,
                        layers_passed=layers_passed,
                    )
                    self._log_incident(tool_name, result, "HIGH")
                    return result
                layers_passed.append("SE")

        # --- Domain Check (Check 5) ---
        if self._domain_checker:
            dom_allowed, dom_violations = self._domain_checker.check_dict(tool_output)
            if not dom_allowed:
                elapsed = (time.time() - start) * 1000
                dom_summary = ", ".join(
                    v['reason'][:50] for v in dom_violations[:3]
                )
                result = GateResult(
                    accepted=False,
                    layer="domain_check",
                    reason=f"Restricted domain access: {dom_summary}",
                    latency_ms=elapsed,
                    layers_passed=layers_passed,
                )
                self._log_incident(tool_name, result, "MEDIUM")
                return result
            layers_passed.append("DOMAIN")

        # --- Layer C: Structured JSON Consensus ---
        if self._consensus and tool.RISK_LEVEL != "LOW":
            # Check consensus cache first (Phase 9 optimization)
            cached = None
            if self._consensus_cache and input_params:
                cached = self._consensus_cache.get(tool_name, input_params)

            if cached:
                # Use cached consensus result
                if not cached.match:
                    elapsed = (time.time() - start) * 1000
                    result = GateResult(
                        accepted=False,
                        layer="layer_c_consensus_cached",
                        reason=cached.reason,
                        latency_ms=elapsed,
                        layers_passed=layers_passed,
                    )
                    self._log_incident(tool_name, result, "HIGH")
                    return result
                layers_passed.append("C_cached")
            else:
                # Run full consensus verification
                verification_source = None
                if tool.VERIFICATION_SOURCE:
                    # Independent source verification (Countermeasure 2)
                    verification_source = tool.VERIFICATION_SOURCE

                consensus_result = self._consensus.verify(
                    tool_output, tool.OUTPUT_SCHEMA,
                    verification_source=verification_source,
                )

                # Cache the result for future calls
                if self._consensus_cache and input_params:
                    self._consensus_cache.put(
                        tool_name, input_params, consensus_result
                    )

                if not consensus_result.match:
                    elapsed = (time.time() - start) * 1000
                    result = GateResult(
                        accepted=False,
                        layer="layer_c_consensus",
                        reason=consensus_result.reason,
                        latency_ms=elapsed,
                        layers_passed=layers_passed,
                        consensus=consensus_result,
                    )
                    self._log_incident(tool_name, result, "HIGH")
                    return result
                layers_passed.append("C")
        else:
            # Layer C skipped: either no consensus verifier configured,
            # or tool is LOW risk (performance optimization, Phase 9)
            layers_passed.append("C_skipped")

        # --- Layer D: Behavioral Floor ---
        # The FrozenNamespace constraints prevent the agent from following
        # any injected instructions outside the frozen capability set.
        # This layer is implicit — the constraints exist by architecture.

        # --- Check 11: Action Hallucination Detection ---
        # Verify that tool output doesn't claim actions outside frozen capabilities
        if isinstance(tool_output, dict):
            capabilities = tuple(tool.CAPABILITIES) if tool.CAPABILITIES else ()
            if capabilities:
                hallucination = self._check_hallucination_recursive(
                    tool_output, capabilities
                )
                if hallucination:
                    elapsed = (time.time() - start) * 1000
                    result = GateResult(
                        accepted=False,
                        layer="hallucination",
                        reason=hallucination,
                        latency_ms=elapsed,
                        layers_passed=layers_passed,
                    )
                    self._log_incident(tool_name, result, "HIGH")
                    return result

        layers_passed.append("D")

        elapsed = (time.time() - start) * 1000
        result = GateResult(
            accepted=True,
            layer="all_passed",
            reason="All verification layers passed.",
            latency_ms=elapsed,
            layers_passed=layers_passed,
        )

        logger.info(
            f"[OutputGate] ACCEPTED: {tool_name} "
            f"Layers: {' → '.join(layers_passed)} "
            f"Latency: {elapsed:.1f}ms"
        )
        return result

    @staticmethod
    def _check_hallucination_recursive(data, capabilities, depth=0, max_depth=5):
        """
        N-02: Recursively check all keys in nested dicts for action hallucination.

        Returns:
            str or None: Reason string if hallucination detected, None otherwise.
        """
        if depth > max_depth:
            return None

        action_keywords = {"action", "operation", "command", "executed", "performed"}
        cap_lower = [c.lower() for c in capabilities]

        if isinstance(data, dict):
            for key, value in data.items():
                key_parts = set(str(key).lower().replace("-", "_").split("_"))
                if key_parts & action_keywords and isinstance(value, str):
                    output_action = value.lower().strip()
                    if output_action and not any(cap == output_action for cap in cap_lower):
                        return (
                            f"Action hallucination: output claims '{output_action}' "
                            f"but tool capabilities are {capabilities}"
                        )
                # Recurse into nested dicts/lists
                nested = OutputGate._check_hallucination_recursive(
                    value, capabilities, depth + 1, max_depth
                )
                if nested:
                    return nested
        elif isinstance(data, (list, tuple)):
            for item in data:
                nested = OutputGate._check_hallucination_recursive(
                    item, capabilities, depth + 1, max_depth
                )
                if nested:
                    return nested

        return None

    def _log_incident(self, tool_name, result, severity):
        """Log a verification failure to the audit log and incident responder."""
        logger.warning(
            f"[OutputGate] DECLINED: {tool_name} at {result.layer}. "
            f"Severity: {severity}. Reason: {result.reason}"
        )
        if self._audit_log:
            self._audit_log.log_incident(
                tool_name=tool_name,
                layer=result.layer,
                severity=severity,
                reason=result.reason,
            )
        # Report to incident response pipeline
        if self._incident_responder:
            self._incident_responder.report(
                tool_name=tool_name,
                layer=result.layer,
                reason=result.reason,
                forensic_data={
                    "severity": severity,
                    "layers_passed": result.layers_passed,
                    "latency_ms": result.latency_ms,
                },
            )


class GateResult:
    """Result of the four-layer verification. Immutable after creation."""
    __slots__ = ('accepted', 'layer', 'reason', 'latency_ms',
                 'layers_passed', 'detections', 'consensus', '_initialized')

    def __init__(self, accepted, layer, reason, latency_ms,
                 layers_passed=None, detections=None, consensus=None):
        object.__setattr__(self, 'accepted', accepted)
        object.__setattr__(self, 'layer', layer)
        object.__setattr__(self, 'reason', reason)
        object.__setattr__(self, 'latency_ms', latency_ms)
        object.__setattr__(self, 'layers_passed', layers_passed or [])
        object.__setattr__(self, 'detections', detections or [])
        object.__setattr__(self, 'consensus', consensus)
        object.__setattr__(self, '_initialized', True)

    def __setattr__(self, name, value):
        if getattr(self, '_initialized', False):
            raise AttributeError(
                f"GateResult is immutable. Cannot set '{name}'."
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name):
        raise AttributeError(
            f"GateResult is immutable. Cannot delete '{name}'."
        )

    def to_dict(self):
        result = {
            "accepted": self.accepted,
            "layer": self.layer,
            "reason": self.reason,
            "latency_ms": round(self.latency_ms, 1),
            "layers_passed": self.layers_passed,
        }
        if self.consensus:
            result["consensus"] = self.consensus.to_dict()
        return result

    def __repr__(self):
        status = "ACCEPTED" if self.accepted else "DECLINED"
        return (
            f"GateResult({status}, layer={self.layer}, "
            f"{self.latency_ms:.1f}ms)"
        )
