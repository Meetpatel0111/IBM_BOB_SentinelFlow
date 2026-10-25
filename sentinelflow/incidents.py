"""
SentinelFlow - incidents.py
============================
Incident manager: creates, tracks, and manages the lifecycle of security
incidents produced by the correlation and scoring pipeline.

Status state machine
--------------------
Valid transitions are defined in ALLOWED_TRANSITIONS.  Attempting an
invalid transition raises IncidentTransitionError.

    OPEN
      |
      +---> INVESTIGATING
      |           |
      |           +---> AWAITING_APPROVAL
      |           |           |
      |           |           +---> CONTAINMENT_PENDING
      |           |           |             |
      |           |           |             +---> CONTAINED
      |           |           |                      |
      |           |           |                      +---> RESOLVED
      |           |           |
      |           +---> FALSE_POSITIVE
      |
      +---> FALSE_POSITIVE   (direct, e.g. auto-dismissed low-risk)

Note: CONTAINED and RESOLVED are defined in the state machine but will not
be set during Phase 2 — containment has not been implemented yet.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import pandas as pd

from sentinelflow.correlation import Incident
from sentinelflow.scoring import score_incident, score_all

# ---------------------------------------------------------------------------
# Status enum
# ---------------------------------------------------------------------------

class IncidentStatus(str, Enum):
    OPEN                = "OPEN"
    INVESTIGATING       = "INVESTIGATING"
    AWAITING_APPROVAL   = "AWAITING_APPROVAL"
    CONTAINMENT_PENDING = "CONTAINMENT_PENDING"
    CONTAINED           = "CONTAINED"
    RESOLVED            = "RESOLVED"
    FALSE_POSITIVE      = "FALSE_POSITIVE"


# Allowed status transitions: {current: {allowed next states}}
ALLOWED_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.OPEN: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.FALSE_POSITIVE,
    },
    IncidentStatus.INVESTIGATING: {
        IncidentStatus.AWAITING_APPROVAL,
        IncidentStatus.FALSE_POSITIVE,
    },
    IncidentStatus.AWAITING_APPROVAL: {
        IncidentStatus.CONTAINMENT_PENDING,
        IncidentStatus.FALSE_POSITIVE,
    },
    IncidentStatus.CONTAINMENT_PENDING: {
        IncidentStatus.CONTAINED,
        IncidentStatus.FALSE_POSITIVE,
    },
    IncidentStatus.CONTAINED: {
        IncidentStatus.RESOLVED,
    },
    IncidentStatus.RESOLVED:        set(),   # terminal
    IncidentStatus.FALSE_POSITIVE:  set(),   # terminal
}

SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1,
}


# ---------------------------------------------------------------------------
# IncidentRecord — managed wrapper around Incident + score + lifecycle
# ---------------------------------------------------------------------------

@dataclass
class IncidentRecord:
    """A managed incident with status, score, and analyst history."""

    incident: Incident
    risk_score: float
    status: IncidentStatus = IncidentStatus.OPEN
    analyst_notes: list[str] = field(default_factory=list)
    status_history: list[dict] = field(default_factory=list)
    created_at: pd.Timestamp = field(default_factory=lambda: pd.Timestamp.now("UTC"))
    updated_at: pd.Timestamp = field(default_factory=lambda: pd.Timestamp.now("UTC"))

    @property
    def incident_id(self) -> str:
        return self.incident.incident_id

    @property
    def max_severity(self) -> str:
        """Return the highest severity across all detections in this incident."""
        sevs = self.incident.severities
        if not sevs:
            return "INFO"
        return max(sevs, key=lambda s: SEVERITY_RANK.get(s.upper(), 0))

    def transition_to(self, new_status: IncidentStatus, note: str = "") -> None:
        """Transition to ``new_status`` if the move is valid.

        Parameters
        ----------
        new_status:
            Target status.
        note:
            Optional analyst note to record with this transition.

        Raises
        ------
        IncidentTransitionError
            If the transition is not allowed from the current status.
        """
        allowed = ALLOWED_TRANSITIONS.get(self.status, set())
        if new_status not in allowed:
            raise IncidentTransitionError(
                f"Cannot transition '{self.incident_id}' from "
                f"{self.status.value} to {new_status.value}. "
                f"Allowed: {[s.value for s in allowed] or 'none (terminal state)'}."
            )
        now = pd.Timestamp.now("UTC")
        self.status_history.append({
            "from":      self.status.value,
            "to":        new_status.value,
            "timestamp": now.isoformat(),
            "note":      note,
        })
        self.status = new_status
        self.updated_at = now
        if note:
            self.analyst_notes.append(f"[{now.isoformat()}] {note}")

    def add_note(self, note: str) -> None:
        """Append a free-text analyst note."""
        now = pd.Timestamp.now("UTC")
        self.analyst_notes.append(f"[{now.isoformat()}] {note}")
        self.updated_at = now

    def to_dict(self) -> dict:
        return {
            "incident_id":         self.incident_id,
            "status":              self.status.value,
            "risk_score":          self.risk_score,
            "max_severity":        self.max_severity,
            "username":            self.incident.username,
            "source_ip":           self.incident.source_ip,
            "affected_hosts":      self.incident.affected_hosts,
            "detection_types":     self.incident.detection_types,
            "detection_count":     self.incident.detection_count,
            "event_count":         self.incident.event_count,
            "incident_start":      self.incident.incident_start.isoformat(),
            "incident_last_seen":  self.incident.incident_last_seen.isoformat(),
            "supporting_event_ids": self.incident.supporting_event_ids,
            "analyst_notes":       self.analyst_notes,
            "status_history":      self.status_history,
            "created_at":          self.created_at.isoformat(),
            "updated_at":          self.updated_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# IncidentManager
# ---------------------------------------------------------------------------

class IncidentManager:
    """Creates, stores, prioritises, and manages IncidentRecord lifecycle.

    Usage
    -----
        mgr = IncidentManager()
        mgr.load_incidents(incidents, scores)
        queue = mgr.get_priority_queue()
        mgr.transition(queue[0].incident_id, IncidentStatus.INVESTIGATING, note="Analyst assigned")
    """

    def __init__(self) -> None:
        self._records: dict[str, IncidentRecord] = {}

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def load_incidents(
        self,
        incidents: list[Incident],
        scores: dict[str, float],
    ) -> list[IncidentRecord]:
        """Create IncidentRecord objects and add them to the manager.

        Existing records (same incident_id) are NOT overwritten.  This
        allows incremental loading without losing analyst state.

        Parameters
        ----------
        incidents:
            Output of ``correlation.correlate()``.
        scores:
            Output of ``scoring.score_all()`` — maps incident_id → float.

        Returns
        -------
        list[IncidentRecord] — newly created records only.
        """
        created: list[IncidentRecord] = []
        for inc in incidents:
            if inc.incident_id in self._records:
                continue
            score = scores.get(inc.incident_id, 0.0)
            rec = IncidentRecord(incident=inc, risk_score=score)
            self._records[inc.incident_id] = rec
            created.append(rec)
        return created

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def get(self, incident_id: str) -> IncidentRecord:
        """Retrieve a record by ID.

        Raises
        ------
        KeyError if the incident_id is not found.
        """
        if incident_id not in self._records:
            raise KeyError(f"Incident '{incident_id}' not found.")
        return self._records[incident_id]

    def list_all(self) -> list[IncidentRecord]:
        """Return all records, sorted by risk_score descending."""
        return sorted(
            self._records.values(),
            key=lambda r: r.risk_score,
            reverse=True,
        )

    def get_priority_queue(
        self,
        status_filter: Optional[list[IncidentStatus]] = None,
    ) -> list[IncidentRecord]:
        """Return incidents sorted by risk_score desc, then severity desc.

        Parameters
        ----------
        status_filter:
            If provided, only include incidents whose status is in this list.
            Pass ``[IncidentStatus.OPEN]`` to get the analyst work queue.
        """
        records = list(self._records.values())
        if status_filter:
            records = [r for r in records if r.status in status_filter]
        return sorted(
            records,
            key=lambda r: (r.risk_score, SEVERITY_RANK.get(r.max_severity, 0)),
            reverse=True,
        )

    def count_by_status(self) -> dict[str, int]:
        """Return a count of records per status value."""
        counts: dict[str, int] = {s.value: 0 for s in IncidentStatus}
        for r in self._records.values():
            counts[r.status.value] += 1
        return counts

    # ------------------------------------------------------------------
    # Lifecycle management
    # ------------------------------------------------------------------

    def transition(
        self,
        incident_id: str,
        new_status: IncidentStatus,
        note: str = "",
    ) -> IncidentRecord:
        """Transition an incident to a new status.

        Raises
        ------
        KeyError             — incident not found.
        IncidentTransitionError — invalid status transition.
        """
        rec = self.get(incident_id)
        rec.transition_to(new_status, note=note)
        return rec

    def add_note(self, incident_id: str, note: str) -> IncidentRecord:
        """Add an analyst note to an incident."""
        rec = self.get(incident_id)
        rec.add_note(note)
        return rec

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        """Serialise all records to a JSON string."""
        return json.dumps(
            [r.to_dict() for r in self.list_all()],
            indent=indent,
            default=str,
        )

    def summary_dataframe(self) -> pd.DataFrame:
        """Return a summary DataFrame of all incidents (one row per incident)."""
        rows = []
        for r in self.list_all():
            rows.append({
                "incident_id":      r.incident_id,
                "status":           r.status.value,
                "risk_score":       r.risk_score,
                "max_severity":     r.max_severity,
                "username":         r.incident.username,
                "source_ip":        r.incident.source_ip,
                "detection_types":  ", ".join(r.incident.detection_types),
                "detection_count":  r.incident.detection_count,
                "event_count":      r.incident.event_count,
                "affected_hosts":   len(r.incident.affected_hosts),
                "incident_start":   r.incident.incident_start,
                "incident_last_seen": r.incident.incident_last_seen,
            })
        return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class IncidentTransitionError(ValueError):
    """Raised when an invalid status transition is attempted."""
