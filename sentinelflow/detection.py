"""
SentinelFlow - detection.py
============================
Rule-based detection engine for suspicious authentication activity.

Detection rules
---------------
RULE-BF   Brute Force
          >= BRUTE_FORCE_THRESHOLD Failure events for the same (username,
          source_ip) pair within BRUTE_FORCE_WINDOW seconds.

RULE-CS   Credential Stuffing
          >= CRED_STUFF_ACCT_THRESHOLD distinct usernames targeted from
          the same source_ip within CRED_STUFF_WINDOW seconds.

RULE-SF   Success-after-Failure
          A Failure followed by a Success for the same (username, source_ip)
          within SUCCESS_AFTER_FAIL_WINDOW seconds, when the failure count
          in that window meets or exceeds SUCCESS_AFTER_FAIL_MIN_FAILS.

RULE-OH   Off-Hours Access
          A Successful login whose UTC hour falls outside
          [OFF_HOURS_BIZ_START, OFF_HOURS_BIZ_END).

RULE-LM   Lateral Movement
          One account authenticates successfully to >= LATERAL_MOVEMENT_HOST_THRESHOLD
          distinct destination_hosts within LATERAL_MOVEMENT_WINDOW seconds.

Design contract
---------------
* Ground-truth columns (scenario_label, is_suspicious) are NEVER read
  by any rule function.  They are permitted in the input DataFrame only
  because ingestion preserves them; the detection engine ignores them.
* All configuration values are module-level constants that can be
  overridden at call-site via keyword arguments.
* Each Detection record carries a `ground_truth_label` field populated
  from the *triggering event*'s is_suspicious value AFTER detection, for
  evaluation purposes only.  This field is set by the caller (evaluate()),
  never inside the rule itself.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import timezone
from typing import Optional

import pandas as pd

# ---------------------------------------------------------------------------
# Configurable thresholds (override via keyword argument on detect_all)
# ---------------------------------------------------------------------------

# RULE-BF
BRUTE_FORCE_THRESHOLD: int = 5          # failures required
BRUTE_FORCE_WINDOW: int = 300           # seconds (5 min)

# RULE-CS
CRED_STUFF_ACCT_THRESHOLD: int = 5      # distinct accounts required
CRED_STUFF_WINDOW: int = 600            # seconds (10 min)

# RULE-SF
SUCCESS_AFTER_FAIL_MIN_FAILS: int = 3   # failures before the success
SUCCESS_AFTER_FAIL_WINDOW: int = 600    # seconds (10 min)

# RULE-OH
OFF_HOURS_BIZ_START: int = 6            # 06:00 UTC (inclusive)
OFF_HOURS_BIZ_END: int = 22             # 22:00 UTC (exclusive)

# RULE-LM
LATERAL_MOVEMENT_HOST_THRESHOLD: int = 3   # distinct destinations required
LATERAL_MOVEMENT_WINDOW: int = 900         # seconds (15 min)

# Severity mapping
SEVERITY_MAP: dict[str, str] = {
    "RULE-BF": "HIGH",
    "RULE-CS": "HIGH",
    "RULE-SF": "CRITICAL",
    "RULE-OH": "MEDIUM",
    "RULE-LM": "HIGH",
}


# ---------------------------------------------------------------------------
# Detection record
# ---------------------------------------------------------------------------

@dataclass
class Detection:
    """A single finding produced by one detection rule."""

    detection_id: str           # stable deterministic hash of key fields
    rule_id: str                # e.g. "RULE-BF"
    rule_name: str              # human-readable name
    severity: str               # CRITICAL | HIGH | MEDIUM | LOW | INFO
    username: str
    source_ip: str
    destination_host: str       # primary affected host (or "MULTIPLE")
    detected_at: pd.Timestamp   # timestamp of the triggering / last event
    supporting_event_ids: list[str]   # event_ids that triggered this finding
    explanation: str            # one-sentence human-readable description
    # Populated AFTER detection for evaluation only — never used as a feature
    ground_truth_label: Optional[int] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        return {
            "detection_id": self.detection_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "username": self.username,
            "source_ip": self.source_ip,
            "destination_host": self.destination_host,
            "detected_at": self.detected_at.isoformat(),
            "supporting_event_ids": self.supporting_event_ids,
            "explanation": self.explanation,
            "ground_truth_label": self.ground_truth_label,
        }


# ---------------------------------------------------------------------------
# Stable detection-ID helper
# ---------------------------------------------------------------------------

def _detection_id(rule_id: str, username: str, source_ip: str, window_start: pd.Timestamp) -> str:
    """Produce a stable 12-char hex ID for a detection."""
    key = f"{rule_id}|{username}|{source_ip}|{window_start.isoformat()}"
    return "DET-" + hashlib.sha256(key.encode()).hexdigest()[:8].upper()


# ---------------------------------------------------------------------------
# RULE-BF: Brute Force
# ---------------------------------------------------------------------------

def detect_brute_force(
    df: pd.DataFrame,
    threshold: int = BRUTE_FORCE_THRESHOLD,
    window_seconds: int = BRUTE_FORCE_WINDOW,
) -> list[Detection]:
    """Detect repeated authentication failures for the same (user, source_ip).

    A detection is raised for every *non-overlapping* window in which
    `threshold` or more failures are observed.  Once a window closes (the
    last failure in the group), a new group may open.
    """
    detections: list[Detection] = []
    failures = df[df["event_outcome"] == "Failure"].copy()
    if failures.empty:
        return detections

    for (username, source_ip), grp in failures.groupby(["username", "source_ip"]):
        grp = grp.sort_values("timestamp")
        events = list(grp.itertuples(index=False))
        i = 0
        while i < len(events):
            window_start = events[i].timestamp
            window_end = window_start + pd.Timedelta(seconds=window_seconds)
            bucket = [e for e in events[i:] if e.timestamp <= window_end]
            if len(bucket) >= threshold:
                ids = [e.event_id for e in bucket]
                last_ts = bucket[-1].timestamp
                det = Detection(
                    detection_id=_detection_id("RULE-BF", username, source_ip, window_start),
                    rule_id="RULE-BF",
                    rule_name="Brute Force",
                    severity=SEVERITY_MAP["RULE-BF"],
                    username=username,
                    source_ip=source_ip,
                    destination_host=bucket[0].destination_host,
                    detected_at=last_ts,
                    supporting_event_ids=ids,
                    explanation=(
                        f"{len(ids)} failed login attempts for '{username}' "
                        f"from {source_ip} within {window_seconds // 60} min."
                    ),
                )
                detections.append(det)
                i += len(bucket)   # advance past this window
            else:
                i += 1
    return detections


# ---------------------------------------------------------------------------
# RULE-CS: Credential Stuffing
# ---------------------------------------------------------------------------

def detect_cred_stuffing(
    df: pd.DataFrame,
    acct_threshold: int = CRED_STUFF_ACCT_THRESHOLD,
    window_seconds: int = CRED_STUFF_WINDOW,
) -> list[Detection]:
    """Detect a single source_ip targeting many distinct usernames with Failures."""
    detections: list[Detection] = []
    failures = df[df["event_outcome"] == "Failure"].copy()
    if failures.empty:
        return detections

    for source_ip, grp in failures.groupby("source_ip"):
        grp = grp.sort_values("timestamp")
        events = list(grp.itertuples(index=False))
        i = 0
        while i < len(events):
            window_start = events[i].timestamp
            window_end = window_start + pd.Timedelta(seconds=window_seconds)
            bucket = [e for e in events[i:] if e.timestamp <= window_end]
            distinct_users = {e.username for e in bucket}
            if len(distinct_users) >= acct_threshold:
                ids = [e.event_id for e in bucket]
                last_ts = bucket[-1].timestamp
                # Use a representative username (most frequent in bucket)
                rep_user = max(distinct_users, key=lambda u: sum(1 for e in bucket if e.username == u))
                det = Detection(
                    detection_id=_detection_id("RULE-CS", str(source_ip), str(source_ip), window_start),
                    rule_id="RULE-CS",
                    rule_name="Credential Stuffing",
                    severity=SEVERITY_MAP["RULE-CS"],
                    username=f"MULTIPLE ({len(distinct_users)} accounts)",
                    source_ip=str(source_ip),
                    destination_host=bucket[0].destination_host,
                    detected_at=last_ts,
                    supporting_event_ids=ids,
                    explanation=(
                        f"Source {source_ip} attempted logins against "
                        f"{len(distinct_users)} distinct accounts within "
                        f"{window_seconds // 60} min (credential stuffing pattern)."
                    ),
                )
                detections.append(det)
                i += len(bucket)
            else:
                i += 1
    return detections


# ---------------------------------------------------------------------------
# RULE-SF: Success After Failure
# ---------------------------------------------------------------------------

def detect_success_after_failure(
    df: pd.DataFrame,
    min_failures: int = SUCCESS_AFTER_FAIL_MIN_FAILS,
    window_seconds: int = SUCCESS_AFTER_FAIL_WINDOW,
) -> list[Detection]:
    """Detect a Success that follows >= min_failures Failures for the same
    (username, source_ip) within window_seconds."""
    detections: list[Detection] = []

    for (username, source_ip), grp in df.groupby(["username", "source_ip"]):
        grp = grp.sort_values("timestamp")
        successes = grp[grp["event_outcome"] == "Success"]
        failures  = grp[grp["event_outcome"] == "Failure"]
        if successes.empty or failures.empty:
            continue

        for _, succ_row in successes.iterrows():
            succ_ts = succ_row["timestamp"]
            window_start = succ_ts - pd.Timedelta(seconds=window_seconds)
            prior_fails = failures[
                (failures["timestamp"] >= window_start) &
                (failures["timestamp"] < succ_ts)
            ]
            if len(prior_fails) >= min_failures:
                ids = prior_fails["event_id"].tolist() + [succ_row["event_id"]]
                det = Detection(
                    detection_id=_detection_id("RULE-SF", username, source_ip, succ_ts),
                    rule_id="RULE-SF",
                    rule_name="Success After Failure",
                    severity=SEVERITY_MAP["RULE-SF"],
                    username=username,
                    source_ip=source_ip,
                    destination_host=succ_row["destination_host"],
                    detected_at=succ_ts,
                    supporting_event_ids=ids,
                    explanation=(
                        f"Account '{username}' succeeded from {source_ip} after "
                        f"{len(prior_fails)} failure(s) within {window_seconds // 60} min "
                        f"— possible successful brute force or credential reuse."
                    ),
                )
                detections.append(det)
    return detections


# ---------------------------------------------------------------------------
# RULE-OH: Off-Hours Access
# ---------------------------------------------------------------------------

def detect_off_hours(
    df: pd.DataFrame,
    biz_start: int = OFF_HOURS_BIZ_START,
    biz_end: int = OFF_HOURS_BIZ_END,
) -> list[Detection]:
    """Detect Successful logins outside configured business hours (UTC)."""
    detections: list[Detection] = []
    successes = df[df["event_outcome"] == "Success"].copy()
    if successes.empty:
        return detections

    # Extract UTC hour
    successes = successes.copy()
    successes["_hour"] = successes["timestamp"].dt.hour
    off_hours_mask = (successes["_hour"] < biz_start) | (successes["_hour"] >= biz_end)
    off_events = successes[off_hours_mask]

    for _, row in off_events.iterrows():
        det = Detection(
            detection_id=_detection_id("RULE-OH", row["username"], row["source_ip"], row["timestamp"]),
            rule_id="RULE-OH",
            rule_name="Off-Hours Access",
            severity=SEVERITY_MAP["RULE-OH"],
            username=row["username"],
            source_ip=row["source_ip"],
            destination_host=row["destination_host"],
            detected_at=row["timestamp"],
            supporting_event_ids=[row["event_id"]],
            explanation=(
                f"Successful login by '{row['username']}' from {row['source_ip']} "
                f"at {row['timestamp'].strftime('%H:%M UTC')} "
                f"(outside business hours {biz_start:02d}:00–{biz_end:02d}:00 UTC)."
            ),
        )
        detections.append(det)
    return detections


# ---------------------------------------------------------------------------
# RULE-LM: Lateral Movement
# ---------------------------------------------------------------------------

def detect_lateral_movement(
    df: pd.DataFrame,
    host_threshold: int = LATERAL_MOVEMENT_HOST_THRESHOLD,
    window_seconds: int = LATERAL_MOVEMENT_WINDOW,
) -> list[Detection]:
    """Detect one account accessing >= host_threshold distinct destination
    hosts within window_seconds (Success events only)."""
    detections: list[Detection] = []
    successes = df[df["event_outcome"] == "Success"].copy()
    if successes.empty:
        return detections

    for (username, source_ip), grp in successes.groupby(["username", "source_ip"]):
        grp = grp.sort_values("timestamp")
        events = list(grp.itertuples(index=False))
        i = 0
        while i < len(events):
            window_start = events[i].timestamp
            window_end = window_start + pd.Timedelta(seconds=window_seconds)
            bucket = [e for e in events[i:] if e.timestamp <= window_end]
            distinct_hosts = {e.destination_host for e in bucket}
            if len(distinct_hosts) >= host_threshold:
                ids = [e.event_id for e in bucket]
                last_ts = bucket[-1].timestamp
                det = Detection(
                    detection_id=_detection_id("RULE-LM", username, source_ip, window_start),
                    rule_id="RULE-LM",
                    rule_name="Lateral Movement",
                    severity=SEVERITY_MAP["RULE-LM"],
                    username=username,
                    source_ip=source_ip,
                    destination_host="MULTIPLE",
                    detected_at=last_ts,
                    supporting_event_ids=ids,
                    explanation=(
                        f"Account '{username}' from {source_ip} accessed "
                        f"{len(distinct_hosts)} distinct hosts within "
                        f"{window_seconds // 60} min "
                        f"({', '.join(sorted(distinct_hosts))})."
                    ),
                )
                detections.append(det)
                i += len(bucket)
            else:
                i += 1
    return detections


# ---------------------------------------------------------------------------
# Master entry point
# ---------------------------------------------------------------------------

def detect_all(
    df: pd.DataFrame,
    bf_threshold: int = BRUTE_FORCE_THRESHOLD,
    bf_window: int = BRUTE_FORCE_WINDOW,
    cs_acct_threshold: int = CRED_STUFF_ACCT_THRESHOLD,
    cs_window: int = CRED_STUFF_WINDOW,
    sf_min_fails: int = SUCCESS_AFTER_FAIL_MIN_FAILS,
    sf_window: int = SUCCESS_AFTER_FAIL_WINDOW,
    oh_biz_start: int = OFF_HOURS_BIZ_START,
    oh_biz_end: int = OFF_HOURS_BIZ_END,
    lm_host_threshold: int = LATERAL_MOVEMENT_HOST_THRESHOLD,
    lm_window: int = LATERAL_MOVEMENT_WINDOW,
) -> list[Detection]:
    """Run all five detection rules and return a combined list of Detections.

    Ground-truth columns in ``df`` (scenario_label, is_suspicious) are
    completely ignored by this function.  The returned Detection objects have
    ``ground_truth_label = None``; callers can populate that field separately
    for evaluation.

    Parameters
    ----------
    df : pd.DataFrame
        Output of ``ingestion.load_events()``.
    All other parameters override the module-level threshold constants.

    Returns
    -------
    list[Detection] — deduplicated by detection_id, sorted by detected_at.
    """
    if df.empty:
        return []

    all_detections: list[Detection] = []

    all_detections.extend(
        detect_brute_force(df, threshold=bf_threshold, window_seconds=bf_window)
    )
    all_detections.extend(
        detect_cred_stuffing(df, acct_threshold=cs_acct_threshold, window_seconds=cs_window)
    )
    all_detections.extend(
        detect_success_after_failure(df, min_failures=sf_min_fails, window_seconds=sf_window)
    )
    all_detections.extend(
        detect_off_hours(df, biz_start=oh_biz_start, biz_end=oh_biz_end)
    )
    all_detections.extend(
        detect_lateral_movement(df, host_threshold=lm_host_threshold, window_seconds=lm_window)
    )

    # Deduplicate by detection_id (same rule on same window → same ID)
    seen: set[str] = set()
    unique: list[Detection] = []
    for d in all_detections:
        if d.detection_id not in seen:
            seen.add(d.detection_id)
            unique.append(d)

    unique.sort(key=lambda d: d.detected_at)
    return unique


# ---------------------------------------------------------------------------
# Post-detection evaluation helper (uses ground truth — never called by rules)
# ---------------------------------------------------------------------------

def attach_ground_truth(
    detections: list[Detection],
    df: pd.DataFrame,
) -> list[Detection]:
    """Attach ground-truth labels to each Detection for evaluation.

    This function may ONLY be called after detection is complete.
    It reads is_suspicious from df to label each detection based on whether
    any of its supporting events are labelled suspicious.

    The label on the Detection is used ONLY for computing precision/recall;
    it is never fed back into any rule.
    """
    if "is_suspicious" not in df.columns:
        return detections

    id_to_label: dict[str, int] = dict(
        zip(df["event_id"].tolist(), df["is_suspicious"].tolist())
    )
    for det in detections:
        labels = [id_to_label.get(eid, 0) for eid in det.supporting_event_ids]
        det.ground_truth_label = int(any(lbl == 1 for lbl in labels))
    return detections


def evaluate_detections(
    detections: list[Detection],
    df: pd.DataFrame,
) -> dict:
    """Compute event-level precision, recall, F1, and FPR.

    Evaluation unit: *event*.
    Predicted positive  = event_id appears in at least one Detection's
                          supporting_event_ids.
    Ground-truth positive = is_suspicious == 1.

    Returns
    -------
    dict with keys: tp, fp, fn, tn, precision, recall, f1, fpr,
                    total_events, total_detections.
    """
    if "is_suspicious" not in df.columns:
        raise ValueError("Ground-truth column 'is_suspicious' not found in DataFrame.")

    flagged_ids: set[str] = set()
    for det in detections:
        flagged_ids.update(det.supporting_event_ids)

    tp = int(((df["event_id"].isin(flagged_ids)) & (df["is_suspicious"] == 1)).sum())
    fp = int(((df["event_id"].isin(flagged_ids)) & (df["is_suspicious"] == 0)).sum())
    fn = int(((~df["event_id"].isin(flagged_ids)) & (df["is_suspicious"] == 1)).sum())
    tn = int(((~df["event_id"].isin(flagged_ids)) & (df["is_suspicious"] == 0)).sum())

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
        "fpr":       round(fpr, 4),
        "total_events":     len(df),
        "total_detections": len(detections),
    }
