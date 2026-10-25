"""
SentinelFlow - containment.py
==============================
Controlled incident-response simulation engine.

SIMULATION MODE IS ALWAYS ENABLED.
This module NEVER modifies real user accounts, firewall rules, or
endpoints.  All actions are recorded as structured JSON log entries.

Design principles
-----------------
* Every action requires an explicit approval flag to execute.
* A unique action_id is generated per (incident_id, action_type) pair so
  that duplicate submissions are detected and rejected.
* The JSON action log at OUTPUT_PATH is the single source of truth for
  the containment engine and for the verification engine.
* Results are deterministic given the same inputs and approval status.

Supported simulated action types
----------------------------------
  LOCK_ACCOUNT  - Simulate disabling the user account in Active Directory.
  BLOCK_IP      - Simulate adding the source IP to a firewall deny list.
  ISOLATE_HOST  - Simulate quarantining a workstation from the network.

Action lifecycle
----------------
  PENDING  -> APPROVED  -> EXECUTED   (success path)
  PENDING  -> REJECTED               (analyst declined)
  PENDING  -> APPROVED  -> FAILED    (simulated execution error)
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import timezone
from typing import Optional

import pandas as pd

from sentinelflow.incidents import IncidentRecord, IncidentStatus

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OUTPUT_DIR: str = "outputs"
ACTION_LOG_PATH: str = os.path.join(OUTPUT_DIR, "action_log.json")

# Recommendation weights: which action is preferred for each rule combination
_RULE_ACTION_MAP: dict[str, str] = {
    "RULE-BF": "LOCK_ACCOUNT",
    "RULE-CS": "BLOCK_IP",
    "RULE-SF": "LOCK_ACCOUNT",
    "RULE-OH": "LOCK_ACCOUNT",
    "RULE-LM": "ISOLATE_HOST",
}

VALID_ACTION_TYPES: frozenset[str] = frozenset(
    {"LOCK_ACCOUNT", "BLOCK_IP", "ISOLATE_HOST"}
)

# ---------------------------------------------------------------------------
# Action data class
# ---------------------------------------------------------------------------


class ActionStatus(str):
    PENDING  = "PENDING"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    FAILED   = "FAILED"
    REJECTED = "REJECTED"


@dataclass
class ContainmentAction:
    """A single simulated containment action record."""

    action_id:    str                    # stable DET-based hash
    incident_id:  str
    action_type:  str                    # LOCK_ACCOUNT | BLOCK_IP | ISOLATE_HOST
    target:       str                    # username, IP, or hostname
    status:       str                    # ActionStatus constant
    approved:     bool
    recommended_by: str                  # rule_id that drove the recommendation
    created_at:   str                    # ISO-8601 UTC
    executed_at:  Optional[str]          # ISO-8601 UTC or None
    explanation:  str
    result:       Optional[str]          # execution result message or None
    simulation_mode: bool = True         # always True

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items()}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _action_id(incident_id: str, action_type: str, target: str) -> str:
    key = f"{incident_id}|{action_type}|{target}"
    return "ACT-" + hashlib.sha256(key.encode()).hexdigest()[:8].upper()


def _now_iso() -> str:
    return pd.Timestamp.now("UTC").isoformat()


def _load_log(path: str) -> list[dict]:
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return []
    return []


def _save_log(path: str, records: list[dict]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, default=str)


# ---------------------------------------------------------------------------
# Recommendation engine
# ---------------------------------------------------------------------------


def recommend_action(record: IncidentRecord) -> tuple[str, str]:
    """Return (action_type, target) recommended for this incident.

    Priority: RULE-LM > RULE-SF > RULE-BF > RULE-CS > RULE-OH
    Target selection:
      LOCK_ACCOUNT -> incident username
      BLOCK_IP     -> incident source_ip
      ISOLATE_HOST -> first affected host
    """
    priority = ["RULE-LM", "RULE-SF", "RULE-BF", "RULE-CS", "RULE-OH"]
    rules = record.incident.detection_types
    chosen_rule = next((r for r in priority if r in rules), rules[0] if rules else "RULE-BF")
    action_type = _RULE_ACTION_MAP.get(chosen_rule, "LOCK_ACCOUNT")
    if action_type == "LOCK_ACCOUNT":
        target = record.incident.username
    elif action_type == "BLOCK_IP":
        target = record.incident.source_ip
    else:  # ISOLATE_HOST
        hosts = [h for h in record.incident.affected_hosts if h not in ("MULTIPLE", "")]
        target = hosts[0] if hosts else record.incident.source_ip
    return action_type, target


# ---------------------------------------------------------------------------
# Core containment function
# ---------------------------------------------------------------------------


def execute_containment(
    record: IncidentRecord,
    action_type: str,
    target: str,
    approved: bool,
    recommended_by: str = "ANALYST",
    simulate_failure: bool = False,
    log_path: str = ACTION_LOG_PATH,
) -> ContainmentAction:
    """Create and (if approved) execute a simulated containment action.

    Parameters
    ----------
    record:
        The IncidentRecord to act on.
    action_type:
        One of LOCK_ACCOUNT, BLOCK_IP, ISOLATE_HOST.
    target:
        The username, IP address, or hostname to act on.
    approved:
        True = proceed with simulated execution.
        False = record as REJECTED, do not execute.
    recommended_by:
        Rule ID or string that drove this recommendation.
    simulate_failure:
        Force the simulated execution to fail (for testing/demo purposes).
    log_path:
        Path to the JSON action log.

    Returns
    -------
    ContainmentAction

    Raises
    ------
    ValueError   — unknown action_type or duplicate EXECUTED action.
    """
    if action_type not in VALID_ACTION_TYPES:
        raise ValueError(
            f"Unknown action_type '{action_type}'. "
            f"Valid: {sorted(VALID_ACTION_TYPES)}"
        )

    action_id = _action_id(record.incident_id, action_type, target)

    # Duplicate-prevention: reject if an EXECUTED record already exists
    existing = _load_log(log_path)
    for entry in existing:
        if entry.get("action_id") == action_id and entry.get("status") == ActionStatus.EXECUTED:
            raise ValueError(
                f"Action {action_id} has already been EXECUTED for incident "
                f"{record.incident_id}. Duplicate actions are prevented."
            )

    now = _now_iso()

    if not approved:
        action = ContainmentAction(
            action_id      = action_id,
            incident_id    = record.incident_id,
            action_type    = action_type,
            target         = target,
            status         = ActionStatus.REJECTED,
            approved       = False,
            recommended_by = recommended_by,
            created_at     = now,
            executed_at    = None,
            explanation    = (
                f"[SIMULATION] Action {action_type} on '{target}' "
                f"for incident {record.incident_id} was REJECTED by analyst."
            ),
            result         = None,
        )
    else:
        # Simulate execution
        if simulate_failure:
            exec_result = (
                f"[SIMULATION] {action_type} on '{target}' FAILED: "
                "simulated execution error (e.g. target not reachable in simulation)."
            )
            status = ActionStatus.FAILED
        else:
            exec_result = _simulate_action(action_type, target)
            status = ActionStatus.EXECUTED

        action = ContainmentAction(
            action_id      = action_id,
            incident_id    = record.incident_id,
            action_type    = action_type,
            target         = target,
            status         = status,
            approved       = True,
            recommended_by = recommended_by,
            created_at     = now,
            executed_at    = _now_iso(),
            explanation    = (
                f"[SIMULATION] {action_type} on '{target}' for incident "
                f"{record.incident_id}. Status: {status}."
            ),
            result         = exec_result,
        )

        # Advance incident status if execution succeeded
        if status == ActionStatus.EXECUTED:
            try:
                record.transition_to(
                    IncidentStatus.CONTAINMENT_PENDING,
                    note=f"Containment action {action_id} executed: {action_type} on {target}",
                )
            except Exception:
                pass  # already past this state

    # Persist to log
    existing.append(action.to_dict())
    _save_log(log_path, existing)

    return action


# ---------------------------------------------------------------------------
# Simulated action implementations
# ---------------------------------------------------------------------------


def _simulate_action(action_type: str, target: str) -> str:
    """Return a human-readable result string describing the simulated action."""
    if action_type == "LOCK_ACCOUNT":
        return (
            f"[SIMULATION] Account '{target}' marked as DISABLED in simulated "
            "Active Directory. All active sessions invalidated. "
            "No real account was modified."
        )
    if action_type == "BLOCK_IP":
        return (
            f"[SIMULATION] IP address {target} added to simulated firewall "
            "deny list (ingress + egress). No real firewall rule was changed."
        )
    if action_type == "ISOLATE_HOST":
        return (
            f"[SIMULATION] Host '{target}' placed in simulated network quarantine VLAN. "
            "All non-management traffic blocked. No real host was isolated."
        )
    return f"[SIMULATION] Unknown action on '{target}'."


# ---------------------------------------------------------------------------
# Action log reader
# ---------------------------------------------------------------------------


def load_action_log(log_path: str = ACTION_LOG_PATH) -> list[ContainmentAction]:
    """Load all ContainmentAction records from the JSON log."""
    raw = _load_log(log_path)
    actions = []
    for entry in raw:
        actions.append(ContainmentAction(**{
            k: entry.get(k)
            for k in ContainmentAction.__dataclass_fields__
        }))
    return actions


def get_actions_for_incident(
    incident_id: str,
    log_path: str = ACTION_LOG_PATH,
) -> list[ContainmentAction]:
    """Return all ContainmentActions recorded for a given incident_id."""
    return [a for a in load_action_log(log_path) if a.incident_id == incident_id]
