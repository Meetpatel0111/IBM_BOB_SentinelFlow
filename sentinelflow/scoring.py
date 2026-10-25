"""
SentinelFlow - scoring.py
==========================
Computes a transparent, deterministic 0–100 risk score for each Incident.

Formula (documented)
--------------------
The score is the weighted sum of five normalised sub-scores, clamped to [0, 100].

  score = clamp(
      w_sev  * severity_score(incident)   +   # 35 %
      w_det  * detection_diversity_score() +   # 20 %
      w_seq  * sequence_score()           +   # 20 %
      w_host * host_spread_score()        +   # 15 %
      w_rec  * recency_score()            ,   # 10 %
      0, 100
  )

Sub-score definitions
---------------------
severity_score (0–100)
    Maps the highest severity found in the incident's detections:
      CRITICAL → 100,  HIGH → 75,  MEDIUM → 50,  LOW → 25,  INFO → 10

detection_diversity_score (0–100)
    Number of distinct rule_ids contributing to the incident, normalised
    against the total number of rules (5).  More rule types → higher score.
    score = min(distinct_rule_count / TOTAL_RULES, 1.0) * 100

sequence_score (0–100)
    Rewards the attack-sequence pattern of failures-followed-by-success:
    +50 if RULE-SF (success after failure) is present
    +25 if RULE-BF or RULE-CS is also present in the same incident
    +25 if RULE-LM is also present (full kill-chain)

host_spread_score (0–100)
    Normalised count of distinct affected_hosts against HOST_SPREAD_MAX:
    score = min(len(affected_hosts) / HOST_SPREAD_MAX, 1.0) * 100

recency_score (0–100)
    How recent the last observed activity is relative to a reference
    timestamp (default: the latest timestamp in the dataset).  Events
    within the last hour score 100; events older than RECENCY_MAX_HOURS
    score 0.  Linear interpolation in between.

Weights
-------
  w_sev  = 0.35
  w_det  = 0.20
  w_seq  = 0.20
  w_host = 0.15
  w_rec  = 0.10
  SUM    = 1.00

Limitations
-----------
* The recency component makes absolute scores dependent on the reference
  timestamp.  Scores computed at different times will differ; always pass
  the same reference_ts for a stable comparison within one analysis run.
* The sequence score is rule-id-based and will not detect novel TTPs that
  are not covered by the five implemented rules.
* Scores are not calibrated probabilities; they are relative priority
  indicators.
"""

from __future__ import annotations

import pandas as pd

from sentinelflow.correlation import Incident

# ---------------------------------------------------------------------------
# Weights and constants
# ---------------------------------------------------------------------------

W_SEVERITY  = 0.35
W_DIVERSITY = 0.20
W_SEQUENCE  = 0.20
W_HOST      = 0.15
W_RECENCY   = 0.10

TOTAL_RULES: int = 5          # number of implemented detection rules
HOST_SPREAD_MAX: int = 7      # normalisation ceiling for host count
RECENCY_MAX_HOURS: float = 48.0  # events older than this score 0 for recency

SEVERITY_VALUES: dict[str, float] = {
    "CRITICAL": 100.0,
    "HIGH":      75.0,
    "MEDIUM":    50.0,
    "LOW":       25.0,
    "INFO":      10.0,
}


# ---------------------------------------------------------------------------
# Sub-score helpers
# ---------------------------------------------------------------------------

def _severity_score(incident: Incident) -> float:
    """Return 0–100 based on the highest severity in the incident."""
    best = 0.0
    for sev in incident.severities:
        best = max(best, SEVERITY_VALUES.get(sev.upper(), 0.0))
    return best


def _diversity_score(incident: Incident) -> float:
    """Return 0–100 based on distinct rule types contributing."""
    n = len(set(incident.detection_types))
    return min(n / TOTAL_RULES, 1.0) * 100.0


def _sequence_score(incident: Incident) -> float:
    """Return 0–100 rewarding failure→success→lateral kill-chain pattern."""
    rules = set(incident.detection_types)
    score = 0.0
    if "RULE-SF" in rules:
        score += 50.0
        if "RULE-BF" in rules or "RULE-CS" in rules:
            score += 25.0
        if "RULE-LM" in rules:
            score += 25.0
    elif "RULE-BF" in rules or "RULE-CS" in rules:
        score += 25.0
        if "RULE-LM" in rules:
            score += 25.0
    elif "RULE-LM" in rules:
        score += 30.0
    elif "RULE-OH" in rules:
        score += 20.0
    return min(score, 100.0)


def _host_spread_score(incident: Incident) -> float:
    """Return 0–100 based on number of distinct affected hosts."""
    n = len(set(incident.affected_hosts))
    return min(n / HOST_SPREAD_MAX, 1.0) * 100.0


def _recency_score(incident: Incident, reference_ts: pd.Timestamp) -> float:
    """Return 0–100 based on how recently the incident was last observed."""
    age_hours = (reference_ts - incident.incident_last_seen).total_seconds() / 3600.0
    if age_hours <= 0:
        return 100.0
    if age_hours >= RECENCY_MAX_HOURS:
        return 0.0
    return (1.0 - age_hours / RECENCY_MAX_HOURS) * 100.0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score_incident(
    incident: Incident,
    reference_ts: pd.Timestamp,
) -> float:
    """Compute and return a 0–100 risk score for a single Incident.

    Parameters
    ----------
    incident:
        An Incident from ``correlation.correlate()``.
    reference_ts:
        A fixed reference timestamp (typically the latest event in the
        dataset) used to compute the recency sub-score.  Use the same
        value for all incidents in one analysis run to ensure comparability.

    Returns
    -------
    float in [0.0, 100.0], rounded to 2 decimal places.
    """
    s_sev  = _severity_score(incident)
    s_div  = _diversity_score(incident)
    s_seq  = _sequence_score(incident)
    s_host = _host_spread_score(incident)
    s_rec  = _recency_score(incident, reference_ts)

    raw = (
        W_SEVERITY  * s_sev  +
        W_DIVERSITY * s_div  +
        W_SEQUENCE  * s_seq  +
        W_HOST      * s_host +
        W_RECENCY   * s_rec
    )
    return round(max(0.0, min(100.0, raw)), 2)


def score_all(
    incidents: list[Incident],
    reference_ts: pd.Timestamp | None = None,
) -> dict[str, float]:
    """Score every incident and return a dict mapping incident_id → score.

    Parameters
    ----------
    incidents:
        Output of ``correlation.correlate()``.
    reference_ts:
        Reference timestamp for recency.  If None, uses the latest
        incident_last_seen across all incidents.

    Returns
    -------
    dict[str, float]  — incident_id → risk score (0–100).
    """
    if not incidents:
        return {}

    if reference_ts is None:
        reference_ts = max(i.incident_last_seen for i in incidents)

    return {
        inc.incident_id: score_incident(inc, reference_ts)
        for inc in incidents
    }
