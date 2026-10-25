"""
SentinelFlow - correlation.py
==============================
Groups related Detection records into Incident objects.

Correlation strategy
--------------------
Two detections are merged into the same incident when ALL of these hold:

  1. Same *username*   — different users are never merged.
  2. Same *source_ip*  — different attack sources are never merged.
  3. Their ``detected_at`` timestamps are within CORRELATION_WINDOW seconds.

The third condition prevents unrelated sessions by the same user (hours or
days apart) from inflating a single incident.

Incident identifiers
---------------------
Each Incident receives a stable ID derived from a SHA-256 hash of:
  (sorted supporting detection IDs concatenated with the earliest detection
  timestamp).  Identical input Detections always produce the identical
  Incident ID, making the correlation step deterministic and reproducible.

Deduplication
-------------
If the same Detection object is passed multiple times (identical
detection_id), only one copy is processed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

import pandas as pd

from sentinelflow.detection import Detection

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CORRELATION_WINDOW: int = 3600   # seconds (1 hour)  — detections within this
                                  # gap and sharing user+source are merged.


# ---------------------------------------------------------------------------
# Incident data class
# ---------------------------------------------------------------------------

@dataclass
class Incident:
    """A correlated group of related Detections."""

    incident_id: str                     # stable deterministic hash
    username: str                        # primary affected account (or MULTIPLE)
    source_ip: str                       # originating source (or MULTIPLE)
    affected_hosts: list[str]            # unique destination hosts seen
    detection_ids: list[str]             # DET-* IDs of contributing detections
    supporting_event_ids: list[str]      # all EVT-* IDs across detections
    detection_types: list[str]           # unique rule_ids (e.g. RULE-BF, RULE-LM)
    severities: list[str]                # severities of contributing detections
    incident_start: pd.Timestamp         # earliest detected_at
    incident_last_seen: pd.Timestamp     # latest detected_at
    detection_count: int                 # number of contributing detections
    event_count: int                     # total supporting events

    def to_dict(self) -> dict:
        return {
            "incident_id":           self.incident_id,
            "username":              self.username,
            "source_ip":             self.source_ip,
            "affected_hosts":        self.affected_hosts,
            "detection_ids":         self.detection_ids,
            "supporting_event_ids":  self.supporting_event_ids,
            "detection_types":       self.detection_types,
            "severities":            self.severities,
            "incident_start":        self.incident_start.isoformat(),
            "incident_last_seen":    self.incident_last_seen.isoformat(),
            "detection_count":       self.detection_count,
            "event_count":           self.event_count,
        }


# ---------------------------------------------------------------------------
# Helper: stable incident ID
# ---------------------------------------------------------------------------

def _incident_id(det_ids: list[str], first_ts: pd.Timestamp) -> str:
    """Produce a stable INC-XXXXXXXX identifier."""
    key = "|".join(sorted(det_ids)) + "|" + first_ts.isoformat()
    return "INC-" + hashlib.sha256(key.encode()).hexdigest()[:8].upper()


# ---------------------------------------------------------------------------
# Correlation entry point
# ---------------------------------------------------------------------------

def correlate(
    detections: list[Detection],
    window_seconds: int = CORRELATION_WINDOW,
) -> list[Incident]:
    """Group Detections into Incidents.

    Parameters
    ----------
    detections:
        Output of ``detection.detect_all()``.  May be empty.
    window_seconds:
        Maximum gap in seconds between two detections (same user + source)
        for them to be merged into the same incident.

    Returns
    -------
    list[Incident] sorted by incident_start ascending.
    """
    if not detections:
        return []

    # 1. Deduplicate incoming detections by detection_id
    seen_det_ids: set[str] = set()
    unique_dets: list[Detection] = []
    for d in detections:
        if d.detection_id not in seen_det_ids:
            seen_det_ids.add(d.detection_id)
            unique_dets.append(d)

    # 2. Sort by (username, source_ip, detected_at) for window sweep
    unique_dets.sort(key=lambda d: (d.username, d.source_ip, d.detected_at))

    # 3. Greedy window-based grouping
    groups: list[list[Detection]] = []
    current_group: list[Detection] = [unique_dets[0]]

    for det in unique_dets[1:]:
        prev = current_group[-1]
        same_user   = det.username  == prev.username
        same_source = det.source_ip == prev.source_ip
        gap = (det.detected_at - prev.detected_at).total_seconds()
        within_window = gap <= window_seconds

        if same_user and same_source and within_window:
            current_group.append(det)
        else:
            groups.append(current_group)
            current_group = [det]
    groups.append(current_group)

    # 4. Build Incident objects from groups
    incidents: list[Incident] = []
    for grp in groups:
        det_ids  = [d.detection_id for d in grp]
        evt_ids  = []
        for d in grp:
            for eid in d.supporting_event_ids:
                if eid not in evt_ids:
                    evt_ids.append(eid)

        hosts = []
        for d in grp:
            h = d.destination_host
            if h and h not in hosts:
                hosts.append(h)

        rule_ids = list(dict.fromkeys(d.rule_id for d in grp))
        sevs     = list(dict.fromkeys(d.severity for d in grp))
        timestamps = sorted(d.detected_at for d in grp)

        inc = Incident(
            incident_id          = _incident_id(det_ids, timestamps[0]),
            username             = grp[0].username,
            source_ip            = grp[0].source_ip,
            affected_hosts       = hosts,
            detection_ids        = det_ids,
            supporting_event_ids = evt_ids,
            detection_types      = rule_ids,
            severities           = sevs,
            incident_start       = timestamps[0],
            incident_last_seen   = timestamps[-1],
            detection_count      = len(grp),
            event_count          = len(evt_ids),
        )
        incidents.append(inc)

    incidents.sort(key=lambda i: i.incident_start)
    return incidents
