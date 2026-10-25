"""
SentinelFlow - verification.py
================================
Post-containment verification engine.

Verification checks the *recorded state* in the containment action log to
determine whether a simulated action was actually executed as intended.

Verification does NOT assume that an attack has stopped simply because no
new alert has been generated.  It checks the action log state explicitly.

Verification outcomes
---------------------
  SUCCESS    - The action was EXECUTED and the simulated state matches the
               expected post-containment state.
  FAILED     - The action record exists but shows FAILED status.
  PENDING    - The action exists but has not been executed yet (still PENDING
               or APPROVED but not yet transitioned).
  UNVERIFIED - No matching action record found, or the record is in an
               unexpected state; manual review required.

Lifecycle integration
---------------------
  After a successful verification the incident is transitioned to CONTAINED.
  After a failed verification the incident remains at CONTAINMENT_PENDING
  and a follow-up note is added.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import pandas as pd

from sentinelflow.containment import (
    ActionStatus,
    ContainmentAction,
    get_actions_for_incident,
    ACTION_LOG_PATH,
)
from sentinelflow.incidents import IncidentRecord, IncidentStatus


# ---------------------------------------------------------------------------
# Verification outcome constants
# ---------------------------------------------------------------------------

class VerificationOutcome(str):
    SUCCESS    = "SUCCESS"
    FAILED     = "FAILED"
    PENDING    = "PENDING"
    UNVERIFIED = "UNVERIFIED"


# ---------------------------------------------------------------------------
# Verification record
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    """Result of verifying one containment action."""

    verification_id:  str
    incident_id:      str
    action_id:        str
    action_type:      str
    target:           str
    outcome:          str                 # VerificationOutcome constant
    verified_at:      str                 # ISO-8601 UTC
    evidence:         str                 # description of what was checked
    follow_up_needed: bool
    follow_up_note:   Optional[str]

    def to_dict(self) -> dict:
        return {
            "verification_id":  self.verification_id,
            "incident_id":      self.incident_id,
            "action_id":        self.action_id,
            "action_type":      self.action_type,
            "target":           self.target,
            "outcome":          self.outcome,
            "verified_at":      self.verified_at,
            "evidence":         self.evidence,
            "follow_up_needed": self.follow_up_needed,
            "follow_up_note":   self.follow_up_note,
        }


# ---------------------------------------------------------------------------
# Expected post-containment state (simulated)
# ---------------------------------------------------------------------------

# Maps action_type -> description of expected simulated state after execution
_EXPECTED_STATE: dict[str, str] = {
    "LOCK_ACCOUNT": "Account marked DISABLED in simulated Active Directory",
    "BLOCK_IP":     "IP address present in simulated firewall deny list",
    "ISOLATE_HOST": "Host placed in simulated network quarantine VLAN",
}

# The simulation result strings (from containment.py) must contain these
# substrings for verification to pass
_VERIFICATION_MARKER: dict[str, str] = {
    "LOCK_ACCOUNT": "DISABLED",
    "BLOCK_IP":     "deny list",
    "ISOLATE_HOST": "quarantine",
}


# ---------------------------------------------------------------------------
# Core verification function
# ---------------------------------------------------------------------------

def verify_containment(
    record: IncidentRecord,
    log_path: str = ACTION_LOG_PATH,
) -> list[VerificationResult]:
    """Verify all containment actions recorded for the given incident.

    For each ContainmentAction in the log matching the incident_id:
      - Check its recorded status.
      - For EXECUTED actions: confirm the result string contains the
        expected simulation marker (proving the simulated action ran).
      - Transition the incident to CONTAINED if at least one action
        verified as SUCCESS and the current status allows it.

    Parameters
    ----------
    record:
        The IncidentRecord to verify.
    log_path:
        Path to the JSON action log.

    Returns
    -------
    list[VerificationResult] — one per matching action.
    """
    actions = get_actions_for_incident(record.incident_id, log_path=log_path)
    if not actions:
        now = pd.Timestamp.now("UTC").isoformat()
        return [VerificationResult(
            verification_id  = f"VER-NOACT-{record.incident_id[-8:]}",
            incident_id      = record.incident_id,
            action_id        = "N/A",
            action_type      = "N/A",
            target           = "N/A",
            outcome          = VerificationOutcome.UNVERIFIED,
            verified_at      = now,
            evidence         = "No containment actions found in action log for this incident.",
            follow_up_needed = True,
            follow_up_note   = "Manual investigation required: no action log entry exists.",
        )]

    results: list[VerificationResult] = []
    any_success = False

    for action in actions:
        now = pd.Timestamp.now("UTC").isoformat()
        ver_id = f"VER-{action.action_id[-8:]}"

        if action.status == ActionStatus.EXECUTED:
            # Check result string for the expected simulation marker
            marker = _VERIFICATION_MARKER.get(action.action_type, "")
            result_str = action.result or ""
            if marker and marker.lower() in result_str.lower():
                outcome = VerificationOutcome.SUCCESS
                evidence = (
                    f"Action log entry {action.action_id} shows status=EXECUTED. "
                    f"Result string confirms simulated {action.action_type} on "
                    f"'{action.target}' (marker: '{marker}' found in result). "
                    f"Expected state: {_EXPECTED_STATE.get(action.action_type, 'N/A')}."
                )
                follow_up = False
                follow_up_note = None
                any_success = True
            else:
                outcome = VerificationOutcome.UNVERIFIED
                evidence = (
                    f"Action log entry {action.action_id} shows status=EXECUTED but "
                    f"result string does not contain expected marker '{marker}'. "
                    f"Result: {result_str[:200]}"
                )
                follow_up = True
                follow_up_note = (
                    f"Simulated execution result did not confirm expected state. "
                    f"Re-attempt action or escalate."
                )

        elif action.status == ActionStatus.FAILED:
            outcome = VerificationOutcome.FAILED
            evidence = (
                f"Action log entry {action.action_id} shows status=FAILED. "
                f"Simulated execution did not complete. Result: {action.result or 'N/A'}"
            )
            follow_up = True
            follow_up_note = "Action failed. Retry or choose an alternative containment action."

        elif action.status in (ActionStatus.PENDING, ActionStatus.APPROVED):
            outcome = VerificationOutcome.PENDING
            evidence = (
                f"Action log entry {action.action_id} shows status={action.status}. "
                "Execution has not yet been attempted."
            )
            follow_up = True
            follow_up_note = "Approve and execute the containment action before verifying."

        elif action.status == ActionStatus.REJECTED:
            outcome = VerificationOutcome.UNVERIFIED
            evidence = (
                f"Action log entry {action.action_id} was REJECTED. "
                "No containment was applied."
            )
            follow_up = True
            follow_up_note = "Action was rejected. No containment effect to verify."

        else:
            outcome = VerificationOutcome.UNVERIFIED
            evidence = f"Unknown action status '{action.status}' for {action.action_id}."
            follow_up = True
            follow_up_note = "Unexpected action status. Manual review required."

        results.append(VerificationResult(
            verification_id  = ver_id,
            incident_id      = record.incident_id,
            action_id        = action.action_id,
            action_type      = action.action_type,
            target           = action.target,
            outcome          = outcome,
            verified_at      = now,
            evidence         = evidence,
            follow_up_needed = follow_up,
            follow_up_note   = follow_up_note,
        ))

    # Transition incident to CONTAINED if at least one SUCCESS
    if any_success:
        try:
            record.transition_to(
                IncidentStatus.CONTAINED,
                note="Verification confirmed: at least one containment action executed successfully.",
            )
        except Exception:
            pass  # already CONTAINED or not in a valid state for this transition

        # Mark follow-up if any action still failed/unverified alongside success
        pending_issues = [r for r in results if r.outcome != VerificationOutcome.SUCCESS]
        if pending_issues:
            record.add_note(
                f"Containment partially verified: {len(pending_issues)} action(s) "
                "require follow-up despite overall SUCCESS outcome."
            )
    else:
        record.add_note(
            "Verification did not confirm any successful containment action. "
            "Incident remains open for further investigation."
        )

    return results


# ---------------------------------------------------------------------------
# Batch verification
# ---------------------------------------------------------------------------

def verify_all_pending(
    manager,   # IncidentManager — avoid circular import by keeping it generic
    log_path: str = ACTION_LOG_PATH,
) -> dict[str, list[VerificationResult]]:
    """Verify all incidents currently at CONTAINMENT_PENDING status.

    Parameters
    ----------
    manager : IncidentManager
    log_path : str

    Returns
    -------
    dict mapping incident_id -> list[VerificationResult]
    """
    from sentinelflow.incidents import IncidentStatus
    pending = manager.get_priority_queue(
        status_filter=[IncidentStatus.CONTAINMENT_PENDING]
    )
    return {
        rec.incident_id: verify_containment(rec, log_path=log_path)
        for rec in pending
    }
