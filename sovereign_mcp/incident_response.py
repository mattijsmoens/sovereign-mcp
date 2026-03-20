"""
IncidentResponse — Five-Stage Incident Response Pipeline.
==========================================================
Implements the 5-stage incident response pipeline from the
architecture doc (lines 811-899):

    Stage 1: Detection and Block
    Stage 2: Classification (CRITICAL/HIGH/MEDIUM/LOW)
    Stage 3: Forensic Capture
    Stage 4: Automated Response (quarantine, alerting, escalation)
    Stage 5: Recovery and Hardening

Integrates with AuditLog for forensic storage and OutputGate for
detection triggers.
"""

import time
import uuid
import threading
import json
import logging

logger = logging.getLogger(__name__)


class Incident:
    """A single security incident record."""

    __slots__ = (
        "incident_id", "severity", "tool_name", "layer",
        "reason", "timestamp", "forensic_data", "response_actions",
        "resolved", "resolved_at",
    )

    def __init__(self, severity, tool_name, layer, reason, forensic_data=None):
        self.incident_id = str(uuid.uuid4())
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW
        self.tool_name = tool_name
        self.layer = layer
        self.reason = reason
        self.timestamp = time.time()
        self.forensic_data = forensic_data or {}
        self.response_actions = []
        self.resolved = False
        self.resolved_at = None

    def to_dict(self):
        return {
            "incident_id": self.incident_id,
            "severity": self.severity,
            "tool_name": self.tool_name,
            "layer": self.layer,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "forensic_data": self.forensic_data,
            "response_actions": self.response_actions,
            "resolved": self.resolved,
            "resolved_at": self.resolved_at,
        }


class IncidentResponder:
    """
    Five-stage incident response pipeline.

    Handles detection, classification, forensics, automated response,
    and recovery for security incidents detected by the OutputGate.

    Usage:
        responder = IncidentResponder(
            alert_callback=send_to_pagerduty,
            escalation_threshold=5,
        )

        # When OutputGate detects a violation:
        incident = responder.report(
            tool_name="send_money",
            layer="layer_c_consensus",
            reason="Hash mismatch",
            forensic_data={...},
        )
    """

    # Classification rules (from architecture doc lines 828-836)
    SEVERITY_MAP = {
        "layer_d_behavioral": "CRITICAL",
        "layer_c_consensus": "HIGH",
        "layer_c_consensus_cached": "HIGH",
        "layer_b_deception": "MEDIUM",
        "pii_detection": "HIGH",
        "content_safety": "HIGH",
        "layer_a_schema": "LOW",
        "pre_check": "LOW",
        "rate_limit": "MEDIUM",
        "domain_check": "MEDIUM",
        "identity_check": "HIGH",
        "hallucination": "HIGH",
    }

    def __init__(self, alert_callback=None, escalation_threshold=5,
                 auto_quarantine_on_critical=True):
        """
        Args:
            alert_callback: Callable(incident_dict) for sending alerts.
                           Called for HIGH and CRITICAL incidents.
            escalation_threshold: Number of MEDIUM incidents before
                                 escalating to HIGH.
            auto_quarantine_on_critical: If True, auto-quarantine
                                        on CRITICAL incidents.
        """
        self._incidents = []  # All incidents
        self._quarantined_tools = set()  # Tools currently quarantined
        self._tool_incident_counts = {}  # tool_name -> count
        self._alert_callback = alert_callback
        self._escalation_threshold = escalation_threshold
        self._auto_quarantine = auto_quarantine_on_critical
        self._lock = threading.Lock()

    def report(self, tool_name, layer, reason, forensic_data=None):
        """
        Stage 1 + 2 + 3: Report an incident (detection, classification, forensics).

        Args:
            tool_name: Tool that caused the incident.
            layer: Verification layer that caught it.
            reason: Why the check failed.
            forensic_data: Dict of forensic context (tool output, parameters, etc.)

        Returns:
            Incident: The created incident record.
        """
        # Stage 2: Classification
        severity = self.SEVERITY_MAP.get(layer, "HIGH")  # Unknown layers fail-safe to HIGH

        # Check for escalation (too many MEDIUM incidents -> HIGH)
        with self._lock:
            self._tool_incident_counts[tool_name] = (
                self._tool_incident_counts.get(tool_name, 0) + 1
            )
            count = self._tool_incident_counts[tool_name]

            # Escalation check inside lock to prevent TOCTOU race (M-13)
            if severity == "MEDIUM" and count >= self._escalation_threshold:
                severity = "HIGH"
                logger.warning(
                    f"[IncidentResponse] ESCALATED: '{tool_name}' has "
                    f"{count} incidents, escalating from MEDIUM to HIGH"
                )

        # Stage 3: Forensic capture
        incident = Incident(
            severity=severity,
            tool_name=tool_name,
            layer=layer,
            reason=reason,
            forensic_data=forensic_data,
        )

        with self._lock:
            self._incidents.append(incident)

        logger.warning(
            f"[IncidentResponse] INCIDENT [{severity}]: "
            f"tool='{tool_name}' layer='{layer}' reason='{reason}' "
            f"id={incident.incident_id[:8]}..."
        )

        # Stage 4: Automated response
        self._respond(incident)

        return incident

    def _respond(self, incident):
        """
        Stage 4: Automated response based on severity.

        CRITICAL: Quarantine entire process + alert
        HIGH: Quarantine tool + alert + investigation
        MEDIUM: Log + increment counter + escalate if threshold reached
        LOW: Log only
        """
        if incident.severity == "CRITICAL":
            # Quarantine the tool immediately
            if self._auto_quarantine:
                self.quarantine_tool(incident.tool_name)
                incident.response_actions.append("tool_quarantined")

            # Send immediate alert
            if self._alert_callback:
                try:
                    self._alert_callback(incident.to_dict())
                    incident.response_actions.append("alert_sent")
                except Exception as e:
                    logger.error(
                        f"[IncidentResponse] Alert callback failed: {e}"
                    )
                    incident.response_actions.append(f"alert_failed: {e}")

            incident.response_actions.append("process_quarantine_recommended")
            logger.critical(
                f"[IncidentResponse] CRITICAL RESPONSE: "
                f"Tool '{incident.tool_name}' quarantined. "
                f"Process quarantine recommended."
            )

        elif incident.severity == "HIGH":
            # Quarantine the specific tool (only if auto_quarantine is enabled)
            if self._auto_quarantine:
                self.quarantine_tool(incident.tool_name)
                incident.response_actions.append("tool_quarantined")

            # Send alert
            if self._alert_callback:
                try:
                    self._alert_callback(incident.to_dict())
                    incident.response_actions.append("alert_sent")
                except Exception as e:
                    logger.error(
                        f"[IncidentResponse] Alert callback failed: {e}"
                    )
                    incident.response_actions.append(f"alert_failed: {e}")

            # Automated investigation flag
            incident.response_actions.append("investigation_triggered")
            logger.warning(
                f"[IncidentResponse] HIGH RESPONSE: "
                f"Tool '{incident.tool_name}' quarantined pending review."
            )

        elif incident.severity == "MEDIUM":
            incident.response_actions.append("pattern_logged")
            # Escalation already handled in report()

        else:  # LOW
            incident.response_actions.append("logged_only")

    def quarantine_tool(self, tool_name):
        """
        Quarantine a tool — block all future calls.

        Args:
            tool_name: Tool to quarantine.
        """
        with self._lock:
            self._quarantined_tools.add(tool_name)
        logger.warning(
            f"[IncidentResponse] QUARANTINED: '{tool_name}' "
            f"blocked from future execution."
        )

    def release_tool(self, tool_name):
        """
        Release a quarantined tool (after manual review).

        Args:
            tool_name: Tool to release.
        """
        with self._lock:
            self._quarantined_tools.discard(tool_name)
        logger.info(f"[IncidentResponse] RELEASED: '{tool_name}'")

    def is_quarantined(self, tool_name):
        """Check if a tool is currently quarantined."""
        with self._lock:
            return tool_name in self._quarantined_tools

    def resolve(self, incident_id, resolution_notes=""):
        """
        Stage 5: Mark an incident as resolved.

        Args:
            incident_id: UUID of the incident.
            resolution_notes: What was done to resolve it.

        Returns:
            bool: Whether the incident was found and resolved.
        """
        with self._lock:
            for incident in self._incidents:
                if incident.incident_id == incident_id:
                    incident.resolved = True
                    incident.resolved_at = time.time()
                    incident.response_actions.append(
                        f"resolved: {resolution_notes}"
                    )
                    logger.info(
                        f"[IncidentResponse] RESOLVED: {incident_id[:8]}... "
                        f"Notes: {resolution_notes}"
                    )
                    return True
        return False

    def get_incidents(self, severity=None, tool_name=None, resolved=None, limit=50):
        """
        Query incidents with optional filters.

        Returns:
            list: List of Incident dicts matching the filters.
        """
        with self._lock:
            results = list(self._incidents)

        if severity:
            results = [i for i in results if i.severity == severity]
        if tool_name:
            results = [i for i in results if i.tool_name == tool_name]
        if resolved is not None:
            results = [i for i in results if i.resolved == resolved]

        # Most recent first
        results.sort(key=lambda i: i.timestamp, reverse=True)
        return [i.to_dict() for i in results[:limit]]

    @property
    def quarantined_tools(self):
        """Set of currently quarantined tool names."""
        with self._lock:
            return set(self._quarantined_tools)

    @property
    def stats(self):
        """Incident statistics."""
        with self._lock:
            by_severity = {}
            for incident in self._incidents:
                by_severity[incident.severity] = (
                    by_severity.get(incident.severity, 0) + 1
                )
            return {
                "total_incidents": len(self._incidents),
                "by_severity": by_severity,
                "quarantined_tools": len(self._quarantined_tools),
                "unresolved": sum(
                    1 for i in self._incidents if not i.resolved
                ),
            }
