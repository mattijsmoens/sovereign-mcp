"""
HumanApproval — Human-in-the-Loop Threshold (Countermeasure 3).
================================================================
Above a frozen value threshold, require human approval before execution.
Below the threshold, automatic execution with all verification layers.

The threshold is frozen in FrozenNamespace. The agent cannot raise its
own approval limit. The timeout defaults to DECLINE, not APPROVE.
If the operator is unavailable, nothing happens. Fail-safe.
"""

import time
import math
import uuid
import logging
import threading

logger = logging.getLogger(__name__)


class HumanApprovalChecker:
    """
    Check if an action requires human approval based on frozen thresholds.

    Flow:
        1. Check parameter values against auto_approve_max
        2. If within threshold → auto-approved (still runs all 4 layers)
        3. If above threshold → PAUSED, returns pending result
        4. Caller must obtain human approval and call approve/deny
        5. If timeout expires → auto-DECLINED (fail-safe)
    """

    def __init__(self):
        self.__pending = {}  # request_id -> PendingApproval
        self._lock = threading.Lock()

    def check(self, params, approval_thresholds):
        """
        Check if parameters require human approval.

        Args:
            params: Dict of parameter name -> value.
            approval_thresholds: Dict from FrozenNamespace with:
                - auto_approve_max: maximum value for auto-approval
                - timeout_seconds: how long to wait for human response
                - timeout_default: what to do on timeout ("DECLINE")

        Returns:
            tuple: (auto_approved: bool, reason: str, pending_id: str or None)
                auto_approved=True: action can proceed automatically
                auto_approved=False: action requires human approval (pending_id set)
                                     OR value exceeds hard limit
        """
        # M-11: Proactively clean up expired pending requests (prevents memory leak)
        self._sweep_expired()

        if not approval_thresholds:
            return True, "No approval thresholds defined.", None

        for param_name, thresholds in approval_thresholds.items():
            if param_name not in params:
                continue

            value = params[param_name]
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                continue

            # Reject NaN and Infinity — NaN > auto_max is always False,
            # meaning NaN would silently auto-approve any amount.
            if math.isnan(value) or math.isinf(value):
                return False, (
                    f"Human approval rejected: '{param_name}' = {value} "
                    f"is not a valid finite number."
                ), None

            auto_max = thresholds.get("auto_approve_max")
            if auto_max is None:
                # Missing auto_approve_max — fail-safe: require approval for any value
                logger.warning(
                    f"[HumanApproval] No auto_approve_max for '{param_name}' — "
                    f"requiring approval (fail-safe)."
                )
                auto_max = -1  # Force all positive values to require approval
            if value > auto_max:
                # Above threshold — needs human approval
                timeout = thresholds.get("timeout_seconds", 300)
                pending_id = f"approval_{param_name}_{uuid.uuid4().hex}"

                with self._lock:
                    self.__pending[pending_id] = PendingApproval(
                        param_name=param_name,
                        value=value,
                        threshold=auto_max,
                        timeout_seconds=timeout,
                        created_at=time.time(),
                    )

                logger.info(
                    f"[HumanApproval] PAUSED: {param_name}={value} exceeds "
                    f"auto_approve_max={auto_max}. Pending: {pending_id}. "
                    f"Timeout: {timeout}s"
                )
                return False, (
                    f"Human approval required: '{param_name}' = {value} "
                    f"exceeds auto-approve threshold of {auto_max}. "
                    f"Pending approval ID: {pending_id}"
                ), pending_id

        return True, "All values within auto-approve thresholds.", None

    def approve(self, pending_id):
        """Approve a pending request. Returns (approved: bool, reason: str)."""
        with self._lock:
            pending = self.__pending.pop(pending_id, None)
            if not pending:
                return False, f"Pending request '{pending_id}' not found."

            elapsed = time.time() - pending.created_at
            if elapsed > pending.timeout_seconds:
                return False, (
                    f"Approval timeout: {elapsed:.0f}s elapsed, "
                    f"limit was {pending.timeout_seconds}s. Auto-DECLINED."
                )

            logger.info(f"[HumanApproval] APPROVED: {pending_id}")
            return True, "Approved by human operator."

    def deny(self, pending_id):
        """Deny a pending request."""
        with self._lock:
            pending = self.__pending.pop(pending_id, None)
            if not pending:
                return False, f"Pending request '{pending_id}' not found."
            logger.info(f"[HumanApproval] DENIED: {pending_id}")
            return True, "Denied by human operator."

    def check_timeout(self, pending_id):
        """Check if a pending request has timed out (fail-safe: DECLINE).

        Returns:
            tuple: (timed_out: bool, reason: str, was_already_resolved: bool)
        """
        with self._lock:
            pending = self.__pending.get(pending_id)
            if not pending:
                return True, "Request already resolved.", True

            elapsed = time.time() - pending.created_at
            if elapsed > pending.timeout_seconds:
                self.__pending.pop(pending_id, None)
                logger.warning(
                    f"[HumanApproval] TIMEOUT: {pending_id}. "
                    f"Auto-DECLINED (fail-safe default deny)."
                )
                return True, "Timeout expired. Auto-DECLINED (fail-safe).", False
            return False, f"Still pending. {pending.timeout_seconds - elapsed:.0f}s remaining.", False


    def _sweep_expired(self):
        """M-11/M-12: Proactively remove expired pending requests."""
        now = time.time()
        with self._lock:
            expired_ids = [
                pid for pid, p in self.__pending.items()
                if (now - p.created_at) > p.timeout_seconds
            ]
            for pid in expired_ids:
                del self.__pending[pid]
            if expired_ids:
                logger.debug(
                    f"[HumanApproval] Swept {len(expired_ids)} expired pending requests."
                )


class PendingApproval:
    """Tracks a pending human approval request. Uses __slots__ for safety."""
    __slots__ = ('param_name', 'value', 'threshold', 'timeout_seconds', 'created_at')

    def __init__(self, param_name, value, threshold, timeout_seconds, created_at):
        self.param_name = param_name
        self.value = value
        self.threshold = threshold
        self.timeout_seconds = timeout_seconds
        self.created_at = created_at
