"""
SentinelFlow - tests/test_phase2.py
=====================================
Test suite for Phase 2: ingestion, detection, correlation, scoring, incidents.

Run with:
    cd SentinelFlow
    python -m pytest tests/test_phase2.py -v

Each test class covers one module.  Small deterministic fixtures are built
inline so the tests are self-contained and independent of external state.
The full synthetic dataset (data/synthetic_auth_logs.csv) is used in
integration-level tests only.
"""

from __future__ import annotations

import os
import sys
import io
from datetime import timezone

import pandas as pd
import pytest

# Ensure the package is importable when running from the SentinelFlow directory
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sentinelflow.ingestion import load_events, IngestionError
from sentinelflow.detection import (
    Detection,
    detect_all,
    detect_brute_force,
    detect_cred_stuffing,
    detect_success_after_failure,
    detect_off_hours,
    detect_lateral_movement,
    attach_ground_truth,
    evaluate_detections,
)
from sentinelflow.correlation import correlate, Incident
from sentinelflow.scoring import score_incident, score_all
from sentinelflow.incidents import (
    IncidentManager,
    IncidentRecord,
    IncidentStatus,
    IncidentTransitionError,
)

# ---------------------------------------------------------------------------
# Helpers: minimal fixture builders
# ---------------------------------------------------------------------------

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "synthetic_auth_logs.csv")

_TS_BASE = pd.Timestamp("2025-07-10T09:00:00Z")   # business hours
_TS_OFF  = pd.Timestamp("2025-07-10T02:00:00Z")   # off-hours (02:00 UTC)


def _ts(offset_seconds: int) -> pd.Timestamp:
    return _TS_BASE + pd.Timedelta(seconds=offset_seconds)


def _make_row(
    event_id: str,
    username: str = "alice.morgan",
    source_ip: str = "10.10.1.1",
    source_host: str = "WS-ALICE",
    destination_host: str = "DC-CORP01",
    auth_type: str = "NTLM",
    logon_type: str = "Network",
    event_outcome: str = "Failure",
    timestamp: pd.Timestamp = _TS_BASE,
    scenario_label: str = "benign",
    is_suspicious: int = 0,
) -> dict:
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "username": username,
        "source_ip": source_ip,
        "source_host": source_host,
        "destination_host": destination_host,
        "auth_type": auth_type,
        "logon_type": logon_type,
        "event_outcome": event_outcome,
        "scenario_label": scenario_label,
        "is_suspicious": is_suspicious,
    }


def _df(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal DataFrame from row dicts (timestamps already parsed)."""
    df = pd.DataFrame(rows)
    if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    elif df["timestamp"].dt.tz is None:
        df["timestamp"] = df["timestamp"].dt.tz_localize("UTC")
    return df


# ============================================================================
# 1. Tests for ingestion.py
# ============================================================================

class TestIngestion:
    """Tests for load_events()."""

    def test_loads_valid_dataset(self):
        """The real synthetic dataset must load without error."""
        if not os.path.exists(DATASET_PATH):
            pytest.skip("Dataset not found — run generate_dataset first.")
        df = load_events(DATASET_PATH)
        assert not df.empty
        assert "event_id" in df.columns
        assert pd.api.types.is_datetime64_any_dtype(df["timestamp"])
        # Timestamps must be UTC-aware
        assert df["timestamp"].dt.tz is not None

    def test_sorted_ascending(self):
        """Loaded dataset must be sorted by timestamp ascending."""
        if not os.path.exists(DATASET_PATH):
            pytest.skip("Dataset not found.")
        df = load_events(DATASET_PATH)
        assert df["timestamp"].is_monotonic_increasing

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_events("nonexistent_file_xyz.csv")

    def test_missing_column_raises(self, tmp_path):
        """CSV missing a required column raises IngestionError."""
        bad_csv = tmp_path / "bad.csv"
        bad_csv.write_text("event_id,timestamp,username\nEVT-00000001,2025-07-10T09:00:00Z,alice\n")
        with pytest.raises(IngestionError, match="Missing required columns"):
            load_events(str(bad_csv))

    def test_empty_file_raises(self, tmp_path):
        """An empty CSV raises IngestionError."""
        empty_csv = tmp_path / "empty.csv"
        cols = "event_id,timestamp,username,source_ip,source_host,destination_host,auth_type,logon_type,event_outcome\n"
        empty_csv.write_text(cols)
        with pytest.raises(IngestionError, match="empty"):
            load_events(str(empty_csv))

    def test_invalid_timestamp_raises(self, tmp_path):
        """Unparseable timestamps raise IngestionError."""
        bad_csv = tmp_path / "bad_ts.csv"
        bad_csv.write_text(
            "event_id,timestamp,username,source_ip,source_host,destination_host,"
            "auth_type,logon_type,event_outcome\n"
            "EVT-AABB0011,NOT-A-DATE,alice,10.0.0.1,WS-A,DC01,NTLM,Network,Failure\n"
        )
        with pytest.raises(IngestionError, match="timestamps could not be parsed"):
            load_events(str(bad_csv))

    def test_invalid_vocab_raises(self, tmp_path):
        """event_outcome with an unknown value raises IngestionError."""
        bad_csv = tmp_path / "bad_vocab.csv"
        bad_csv.write_text(
            "event_id,timestamp,username,source_ip,source_host,destination_host,"
            "auth_type,logon_type,event_outcome\n"
            "EVT-AABB0012,2025-07-10T09:00:00Z,alice,10.0.0.1,WS-A,DC01,NTLM,Network,UNKNOWN\n"
        )
        with pytest.raises(IngestionError, match="invalid values"):
            load_events(str(bad_csv))

    def test_no_ground_truth_ok_by_default(self, tmp_path):
        """Dataset without ground-truth columns loads fine (require_ground_truth=False)."""
        csv = tmp_path / "no_gt.csv"
        csv.write_text(
            "event_id,timestamp,username,source_ip,source_host,destination_host,"
            "auth_type,logon_type,event_outcome\n"
            "EVT-AABB0013,2025-07-10T09:00:00Z,alice,10.0.0.1,WS-A,DC01,NTLM,Network,Failure\n"
        )
        df = load_events(str(csv))
        assert len(df) == 1

    def test_require_ground_truth_raises_when_absent(self, tmp_path):
        """require_ground_truth=True raises when columns are missing."""
        csv = tmp_path / "no_gt2.csv"
        csv.write_text(
            "event_id,timestamp,username,source_ip,source_host,destination_host,"
            "auth_type,logon_type,event_outcome\n"
            "EVT-AABB0014,2025-07-10T09:00:00Z,alice,10.0.0.1,WS-A,DC01,NTLM,Network,Failure\n"
        )
        with pytest.raises(IngestionError, match="Ground-truth columns required"):
            load_events(str(csv), require_ground_truth=True)


# ============================================================================
# 2. Tests for detection.py
# ============================================================================

class TestDetectionBruteForce:
    """RULE-BF: Brute Force tests."""

    def test_triggers_on_threshold_failures(self):
        """5 failures for same user+source within 5 min triggers RULE-BF."""
        rows = [_make_row(f"EVT-BF{i:04X}", timestamp=_ts(i * 30)) for i in range(5)]
        df = _df(rows)
        dets = detect_brute_force(df, threshold=5, window_seconds=300)
        assert len(dets) == 1
        assert dets[0].rule_id == "RULE-BF"
        assert dets[0].username == "alice.morgan"

    def test_does_not_trigger_below_threshold(self):
        """4 failures (below threshold=5) must NOT trigger."""
        rows = [_make_row(f"EVT-BF{i:04X}", timestamp=_ts(i * 30)) for i in range(4)]
        df = _df(rows)
        dets = detect_brute_force(df, threshold=5, window_seconds=300)
        assert len(dets) == 0

    def test_does_not_trigger_when_spread_across_long_window(self):
        """5 failures spread over 10 min do not trigger a 5-min window rule."""
        rows = [_make_row(f"EVT-BF{i:04X}", timestamp=_ts(i * 150)) for i in range(5)]
        # gaps: 0, 150, 300, 450, 600 seconds — only 2 fit in a 300-s window
        df = _df(rows)
        dets = detect_brute_force(df, threshold=5, window_seconds=300)
        assert len(dets) == 0

    def test_different_source_ips_not_merged(self):
        """Failures from different source IPs for the same user are counted separately."""
        rows = (
            [_make_row(f"EVT-BF1{i:02X}", source_ip="1.2.3.4", timestamp=_ts(i * 20)) for i in range(5)] +
            [_make_row(f"EVT-BF2{i:02X}", source_ip="5.6.7.8", timestamp=_ts(i * 20)) for i in range(3)]
        )
        df = _df(rows)
        dets = detect_brute_force(df, threshold=5, window_seconds=300)
        # Only the first source_ip group meets the threshold
        assert len(dets) == 1
        assert dets[0].source_ip == "1.2.3.4"

    def test_benign_success_events_ignored(self):
        """Success events must not contribute to brute-force failure count."""
        rows = [_make_row(f"EVT-BN{i:04X}", event_outcome="Success", timestamp=_ts(i * 30)) for i in range(10)]
        df = _df(rows)
        dets = detect_brute_force(df, threshold=5, window_seconds=300)
        assert len(dets) == 0

    def test_ground_truth_not_used(self):
        """Rule must fire based on event_outcome, not on is_suspicious."""
        # Give all events is_suspicious=0 (labelled benign) but real failure pattern
        rows = [
            _make_row(f"EVT-BF{i:04X}", timestamp=_ts(i * 30), is_suspicious=0)
            for i in range(5)
        ]
        df = _df(rows)
        dets = detect_brute_force(df, threshold=5, window_seconds=300)
        # Must still fire even though ground truth says benign
        assert len(dets) == 1


class TestDetectionCredStuffing:
    """RULE-CS: Credential Stuffing tests."""

    def test_triggers_on_multiple_accounts(self):
        """One source IP targeting 5+ distinct users within 10 min."""
        users = ["user_a", "user_b", "user_c", "user_d", "user_e"]
        rows = [
            _make_row(f"EVT-CS{i:04X}", username=u, source_ip="9.9.9.9", timestamp=_ts(i * 60))
            for i, u in enumerate(users)
        ]
        df = _df(rows)
        dets = detect_cred_stuffing(df, acct_threshold=5, window_seconds=600)
        assert len(dets) >= 1
        assert dets[0].rule_id == "RULE-CS"

    def test_does_not_trigger_below_threshold(self):
        """4 distinct users (threshold=5) must NOT trigger."""
        users = ["user_a", "user_b", "user_c", "user_d"]
        rows = [
            _make_row(f"EVT-CS{i:04X}", username=u, source_ip="9.9.9.9", timestamp=_ts(i * 60))
            for i, u in enumerate(users)
        ]
        df = _df(rows)
        dets = detect_cred_stuffing(df, acct_threshold=5, window_seconds=600)
        assert len(dets) == 0

    def test_different_source_ips_not_grouped(self):
        """Each source IP is evaluated independently."""
        users = ["user_a", "user_b", "user_c", "user_d", "user_e"]
        rows = (
            [_make_row(f"EVT-CSA{i:02X}", username=users[i], source_ip="1.1.1.1", timestamp=_ts(i * 60)) for i in range(5)] +
            [_make_row(f"EVT-CSB{i:02X}", username=users[i], source_ip="2.2.2.2", timestamp=_ts(i * 60)) for i in range(3)]
        )
        df = _df(rows)
        dets = detect_cred_stuffing(df, acct_threshold=5, window_seconds=600)
        # Only 1.1.1.1 meets threshold
        assert len(dets) == 1
        assert dets[0].source_ip == "1.1.1.1"


class TestDetectionSuccessAfterFailure:
    """RULE-SF: Success After Failure tests."""

    def test_triggers_after_min_failures(self):
        """3 failures then 1 success within window must trigger RULE-SF."""
        rows = [
            _make_row(f"EVT-SF{i:04X}", event_outcome="Failure", timestamp=_ts(i * 60))
            for i in range(3)
        ] + [
            _make_row("EVT-SF_S", event_outcome="Success", timestamp=_ts(300),
                      is_suspicious=1)
        ]
        df = _df(rows)
        dets = detect_success_after_failure(df, min_failures=3, window_seconds=600)
        assert len(dets) >= 1
        assert dets[0].rule_id == "RULE-SF"

    def test_does_not_trigger_below_min_failures(self):
        """2 failures (min_failures=3) then success must NOT trigger."""
        rows = [
            _make_row(f"EVT-SF{i:04X}", event_outcome="Failure", timestamp=_ts(i * 60))
            for i in range(2)
        ] + [
            _make_row("EVT-SF_S", event_outcome="Success", timestamp=_ts(240))
        ]
        df = _df(rows)
        dets = detect_success_after_failure(df, min_failures=3, window_seconds=600)
        assert len(dets) == 0

    def test_does_not_trigger_success_only(self):
        """Pure success stream should not trigger RULE-SF."""
        rows = [
            _make_row(f"EVT-SF{i:04X}", event_outcome="Success", timestamp=_ts(i * 60))
            for i in range(5)
        ]
        df = _df(rows)
        dets = detect_success_after_failure(df, min_failures=3, window_seconds=600)
        assert len(dets) == 0

    def test_failures_outside_window_not_counted(self):
        """Failures older than the window must not count toward the threshold."""
        # 3 failures, but all > 10 min before the success
        rows = [
            _make_row(f"EVT-SF{i:04X}", event_outcome="Failure", timestamp=_ts(i * 300))
            for i in range(3)  # 0, 300, 600 seconds before base
        ] + [
            _make_row("EVT-SF_S", event_outcome="Success", timestamp=_ts(1200))
            # success at +1200s; window is 600s; failures at 0,300,600 all outside
        ]
        df = _df(rows)
        dets = detect_success_after_failure(df, min_failures=3, window_seconds=600)
        assert len(dets) == 0


class TestDetectionOffHours:
    """RULE-OH: Off-Hours Access tests."""

    def test_triggers_for_off_hours_success(self):
        """A success at 02:00 UTC triggers RULE-OH (biz_start=6)."""
        rows = [_make_row("EVT-OH0001", event_outcome="Success", timestamp=_TS_OFF)]
        df = _df(rows)
        dets = detect_off_hours(df, biz_start=6, biz_end=22)
        assert len(dets) == 1
        assert dets[0].rule_id == "RULE-OH"

    def test_does_not_trigger_during_business_hours(self):
        """A success at 09:00 UTC must NOT trigger RULE-OH."""
        rows = [_make_row("EVT-OH0002", event_outcome="Success", timestamp=_TS_BASE)]
        df = _df(rows)
        dets = detect_off_hours(df, biz_start=6, biz_end=22)
        assert len(dets) == 0

    def test_failure_events_not_flagged(self):
        """RULE-OH only flags successful logins; failures at off-hours are ignored."""
        rows = [_make_row("EVT-OH0003", event_outcome="Failure", timestamp=_TS_OFF)]
        df = _df(rows)
        dets = detect_off_hours(df, biz_start=6, biz_end=22)
        assert len(dets) == 0

    def test_boundary_at_biz_start_is_not_flagged(self):
        """Login exactly at biz_start (06:00 UTC) is NOT off-hours."""
        ts_exact = _TS_BASE.replace(hour=6, minute=0, second=0)
        rows = [_make_row("EVT-OH0004", event_outcome="Success", timestamp=ts_exact)]
        df = _df(rows)
        dets = detect_off_hours(df, biz_start=6, biz_end=22)
        assert len(dets) == 0

    def test_benign_label_not_required(self):
        """The rule must fire based on timestamp, regardless of is_suspicious value."""
        rows = [_make_row("EVT-OH0005", event_outcome="Success",
                          timestamp=_TS_OFF, is_suspicious=0)]
        df = _df(rows)
        dets = detect_off_hours(df, biz_start=6, biz_end=22)
        # Rule fires even though is_suspicious=0 (benign label)
        assert len(dets) == 1


class TestDetectionLateralMovement:
    """RULE-LM: Lateral Movement tests."""

    def test_triggers_on_host_fan_out(self):
        """One user accessing 3+ distinct hosts within 15 min triggers RULE-LM."""
        hosts = ["SRV-A", "SRV-B", "SRV-C"]
        rows = [
            _make_row(f"EVT-LM{i:04X}", destination_host=h,
                      event_outcome="Success", timestamp=_ts(i * 180))
            for i, h in enumerate(hosts)
        ]
        df = _df(rows)
        dets = detect_lateral_movement(df, host_threshold=3, window_seconds=900)
        assert len(dets) >= 1
        assert dets[0].rule_id == "RULE-LM"

    def test_does_not_trigger_below_threshold(self):
        """Accessing 2 hosts (threshold=3) must NOT trigger."""
        rows = [
            _make_row(f"EVT-LM{i:04X}", destination_host=f"SRV-{i}",
                      event_outcome="Success", timestamp=_ts(i * 60))
            for i in range(2)
        ]
        df = _df(rows)
        dets = detect_lateral_movement(df, host_threshold=3, window_seconds=900)
        assert len(dets) == 0

    def test_failure_events_not_counted(self):
        """Lateral movement rule counts only successful authentications."""
        rows = [
            _make_row(f"EVT-LM{i:04X}", destination_host=f"SRV-{i}",
                      event_outcome="Failure", timestamp=_ts(i * 60))
            for i in range(5)
        ]
        df = _df(rows)
        dets = detect_lateral_movement(df, host_threshold=3, window_seconds=900)
        assert len(dets) == 0

    def test_different_users_not_merged(self):
        """Different usernames must not be combined for LM detection."""
        rows = [
            _make_row("EVT-LM0001", username="user_x", destination_host="SRV-A",
                      event_outcome="Success", timestamp=_ts(0)),
            _make_row("EVT-LM0002", username="user_y", destination_host="SRV-B",
                      event_outcome="Success", timestamp=_ts(60)),
            _make_row("EVT-LM0003", username="user_z", destination_host="SRV-C",
                      event_outcome="Success", timestamp=_ts(120)),
        ]
        df = _df(rows)
        dets = detect_lateral_movement(df, host_threshold=3, window_seconds=900)
        assert len(dets) == 0


class TestDetectAll:
    """Integration: detect_all() and ground-truth isolation."""

    def test_detect_all_returns_detections(self):
        """detect_all on the full synthetic dataset returns a non-empty list."""
        if not os.path.exists(DATASET_PATH):
            pytest.skip("Dataset not found.")
        df = load_events(DATASET_PATH)
        dets = detect_all(df)
        assert len(dets) > 0

    def test_detect_all_no_ground_truth_columns_used(self):
        """Running detect_all on a DataFrame without ground-truth columns succeeds."""
        rows = [
            _make_row(f"EVT-DA{i:04X}", event_outcome="Failure", timestamp=_ts(i * 30))
            for i in range(5)
        ]
        df = _df(rows).drop(columns=["scenario_label", "is_suspicious"])
        dets = detect_all(df)
        # Detection still works — no ground truth needed
        assert len(dets) >= 1

    def test_empty_dataframe_returns_empty(self):
        """detect_all on empty DataFrame returns []."""
        cols = [
            "event_id", "timestamp", "username", "source_ip", "source_host",
            "destination_host", "auth_type", "logon_type", "event_outcome",
        ]
        df = pd.DataFrame(columns=cols)
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
        dets = detect_all(df)
        assert dets == []

    def test_detection_ids_are_unique(self):
        """No two Detection objects in the output share a detection_id."""
        if not os.path.exists(DATASET_PATH):
            pytest.skip("Dataset not found.")
        df = load_events(DATASET_PATH)
        dets = detect_all(df)
        ids = [d.detection_id for d in dets]
        assert len(ids) == len(set(ids))

    def test_detection_sorted_by_time(self):
        """detect_all output is sorted ascending by detected_at."""
        if not os.path.exists(DATASET_PATH):
            pytest.skip("Dataset not found.")
        df = load_events(DATASET_PATH)
        dets = detect_all(df)
        timestamps = [d.detected_at for d in dets]
        assert timestamps == sorted(timestamps)


# ============================================================================
# 3. Tests for correlation.py
# ============================================================================

class TestCorrelation:
    """Tests for correlate()."""

    def _make_detection(
        self,
        det_id: str,
        rule_id: str = "RULE-BF",
        username: str = "alice.morgan",
        source_ip: str = "9.9.9.9",
        detected_at: pd.Timestamp = _TS_BASE,
        event_ids: list[str] | None = None,
    ) -> Detection:
        return Detection(
            detection_id=det_id,
            rule_id=rule_id,
            rule_name="Test Rule",
            severity="HIGH",
            username=username,
            source_ip=source_ip,
            destination_host="DC01",
            detected_at=detected_at,
            supporting_event_ids=event_ids or ["EVT-00000001"],
            explanation="Test detection",
        )

    def test_empty_list_returns_empty(self):
        assert correlate([]) == []

    def test_single_detection_becomes_one_incident(self):
        d = self._make_detection("DET-00000001")
        incidents = correlate([d])
        assert len(incidents) == 1

    def test_two_related_detections_merged(self):
        """Same user+source within window → single incident."""
        d1 = self._make_detection("DET-00000001", detected_at=_ts(0))
        d2 = self._make_detection("DET-00000002", detected_at=_ts(1800))  # 30 min later
        incidents = correlate([d1, d2], window_seconds=3600)
        assert len(incidents) == 1
        assert incidents[0].detection_count == 2

    def test_two_detections_outside_window_not_merged(self):
        """Same user+source but gap > window → two separate incidents."""
        d1 = self._make_detection("DET-00000001", detected_at=_ts(0))
        d2 = self._make_detection("DET-00000002", detected_at=_ts(7200))  # 2 h later
        incidents = correlate([d1, d2], window_seconds=3600)
        assert len(incidents) == 2

    def test_different_users_not_merged(self):
        """Different usernames → separate incidents even if within window."""
        d1 = self._make_detection("DET-00000001", username="alice.morgan")
        d2 = self._make_detection("DET-00000002", username="bob.kumar")
        incidents = correlate([d1, d2])
        assert len(incidents) == 2

    def test_different_source_ips_not_merged(self):
        """Different source IPs → separate incidents."""
        d1 = self._make_detection("DET-00000001", source_ip="1.1.1.1")
        d2 = self._make_detection("DET-00000002", source_ip="2.2.2.2")
        incidents = correlate([d1, d2])
        assert len(incidents) == 2

    def test_duplicate_detection_ids_deduplicated(self):
        """Passing the same Detection twice yields one incident with one detection."""
        d1 = self._make_detection("DET-SAME0001")
        d2 = self._make_detection("DET-SAME0001")   # duplicate ID
        incidents = correlate([d1, d2])
        assert len(incidents) == 1
        assert incidents[0].detection_count == 1

    def test_incident_id_is_stable(self):
        """Same detections always produce the same incident_id."""
        d1 = self._make_detection("DET-STABLE01", detected_at=_ts(0))
        d2 = self._make_detection("DET-STABLE02", detected_at=_ts(1800))
        id1 = correlate([d1, d2])[0].incident_id
        id2 = correlate([d1, d2])[0].incident_id
        assert id1 == id2

    def test_supporting_event_ids_preserved(self):
        """All event IDs from all detections appear in the incident."""
        d1 = self._make_detection("DET-EV01", event_ids=["EVT-AAAA0001", "EVT-AAAA0002"])
        d2 = self._make_detection("DET-EV02", event_ids=["EVT-BBBB0001"], detected_at=_ts(1800))
        inc = correlate([d1, d2])[0]
        assert "EVT-AAAA0001" in inc.supporting_event_ids
        assert "EVT-AAAA0002" in inc.supporting_event_ids
        assert "EVT-BBBB0001" in inc.supporting_event_ids

    def test_multiple_rule_types_recorded(self):
        """Different rule_ids appear in detection_types of the merged incident."""
        d1 = self._make_detection("DET-RT01", rule_id="RULE-BF", detected_at=_ts(0))
        d2 = self._make_detection("DET-RT02", rule_id="RULE-LM", detected_at=_ts(600))
        inc = correlate([d1, d2])[0]
        assert "RULE-BF" in inc.detection_types
        assert "RULE-LM" in inc.detection_types

    def test_correlation_on_full_dataset(self):
        """Full dataset produces incidents; incident count < detection count."""
        if not os.path.exists(DATASET_PATH):
            pytest.skip("Dataset not found.")
        df = load_events(DATASET_PATH)
        dets = detect_all(df)
        incidents = correlate(dets)
        assert len(incidents) > 0
        assert len(incidents) <= len(dets)


# ============================================================================
# 4. Tests for scoring.py
# ============================================================================

class TestScoring:
    """Tests for score_incident() and score_all()."""

    def _make_incident(
        self,
        inc_id: str = "INC-00000001",
        username: str = "alice.morgan",
        source_ip: str = "9.9.9.9",
        severities: list[str] | None = None,
        detection_types: list[str] | None = None,
        affected_hosts: list[str] | None = None,
        last_seen: pd.Timestamp = _TS_BASE,
    ) -> Incident:
        from sentinelflow.correlation import Incident
        return Incident(
            incident_id=inc_id,
            username=username,
            source_ip=source_ip,
            affected_hosts=affected_hosts or ["DC01"],
            detection_ids=["DET-ZZZZZ001"],
            supporting_event_ids=["EVT-ZZZZ0001"],
            detection_types=detection_types or ["RULE-BF"],
            severities=severities or ["HIGH"],
            incident_start=_TS_BASE,
            incident_last_seen=last_seen,
            detection_count=1,
            event_count=1,
        )

    def test_score_is_within_bounds(self):
        """Score must always be in [0, 100]."""
        inc = self._make_incident()
        score = score_incident(inc, reference_ts=_TS_BASE)
        assert 0.0 <= score <= 100.0

    def test_critical_scores_higher_than_medium(self):
        """CRITICAL severity incident must score higher than MEDIUM."""
        inc_crit = self._make_incident(inc_id="INC-00000001", severities=["CRITICAL"])
        inc_med  = self._make_incident(inc_id="INC-00000002", severities=["MEDIUM"])
        ref = _TS_BASE
        assert score_incident(inc_crit, ref) > score_incident(inc_med, ref)

    def test_more_rule_types_scores_higher(self):
        """Incident with 3 rule types scores higher than 1 rule type."""
        inc_multi = self._make_incident(inc_id="INC-00000001",
                                        detection_types=["RULE-BF", "RULE-SF", "RULE-LM"],
                                        severities=["HIGH"])
        inc_single = self._make_incident(inc_id="INC-00000002",
                                         detection_types=["RULE-BF"],
                                         severities=["HIGH"])
        ref = _TS_BASE
        assert score_incident(inc_multi, ref) > score_incident(inc_single, ref)

    def test_score_is_deterministic(self):
        """Same incident + same reference_ts → same score every time."""
        inc = self._make_incident()
        ref = _TS_BASE
        s1 = score_incident(inc, ref)
        s2 = score_incident(inc, ref)
        assert s1 == s2

    def test_older_incident_scores_lower_recency(self):
        """An incident from 47 h ago scores lower than one from 1 h ago."""
        old = self._make_incident(inc_id="INC-OLD", last_seen=_TS_BASE - pd.Timedelta(hours=47))
        new = self._make_incident(inc_id="INC-NEW", last_seen=_TS_BASE)
        ref = _TS_BASE
        assert score_incident(new, ref) > score_incident(old, ref)

    def test_score_all_returns_dict(self):
        """score_all returns a dict with one entry per incident."""
        inc1 = self._make_incident("INC-00000001")
        inc2 = self._make_incident("INC-00000002", source_ip="8.8.8.8")
        scores = score_all([inc1, inc2])
        assert "INC-00000001" in scores
        assert "INC-00000002" in scores

    def test_score_all_empty_returns_empty(self):
        assert score_all([]) == {}

    def test_sf_lm_combination_scores_higher_than_oh_alone(self):
        """SF+LM kill-chain should score higher than OH alone."""
        inc_kc = self._make_incident(inc_id="INC-KC",
                                     detection_types=["RULE-SF", "RULE-LM"],
                                     severities=["CRITICAL", "HIGH"])
        inc_oh = self._make_incident(inc_id="INC-OH",
                                     detection_types=["RULE-OH"],
                                     severities=["MEDIUM"])
        ref = _TS_BASE
        assert score_incident(inc_kc, ref) > score_incident(inc_oh, ref)


# ============================================================================
# 5. Tests for incidents.py
# ============================================================================

class TestIncidentManager:
    """Tests for IncidentManager and status transitions."""

    def _make_record(self, inc_id: str = "INC-00000001", score: float = 50.0) -> IncidentRecord:
        from sentinelflow.correlation import Incident
        inc = Incident(
            incident_id=inc_id,
            username="alice.morgan",
            source_ip="9.9.9.9",
            affected_hosts=["DC01"],
            detection_ids=["DET-ZZZZ0001"],
            supporting_event_ids=["EVT-ZZZZ0001"],
            detection_types=["RULE-BF"],
            severities=["HIGH"],
            incident_start=_TS_BASE,
            incident_last_seen=_TS_BASE,
            detection_count=1,
            event_count=1,
        )
        return IncidentRecord(incident=inc, risk_score=score)

    def test_load_incidents_creates_records(self):
        from sentinelflow.correlation import Incident
        inc = Incident(
            incident_id="INC-TEST0001",
            username="alice.morgan",
            source_ip="9.9.9.9",
            affected_hosts=["DC01"],
            detection_ids=["DET-ZZZZ0001"],
            supporting_event_ids=["EVT-ZZZZ0001"],
            detection_types=["RULE-BF"],
            severities=["HIGH"],
            incident_start=_TS_BASE,
            incident_last_seen=_TS_BASE,
            detection_count=1,
            event_count=1,
        )
        mgr = IncidentManager()
        created = mgr.load_incidents([inc], {"INC-TEST0001": 75.0})
        assert len(created) == 1
        assert mgr.get("INC-TEST0001").risk_score == 75.0

    def test_duplicate_load_not_overwritten(self):
        """Loading the same incident_id twice keeps the first record."""
        rec = self._make_record("INC-DUP0001", score=80.0)
        from sentinelflow.correlation import Incident
        inc = rec.incident
        mgr = IncidentManager()
        mgr.load_incidents([inc], {inc.incident_id: 80.0})
        mgr.load_incidents([inc], {inc.incident_id: 30.0})  # should be ignored
        assert mgr.get("INC-DUP0001").risk_score == 80.0

    def test_valid_transition_open_to_investigating(self):
        rec = self._make_record("INC-TRANS01")
        rec.transition_to(IncidentStatus.INVESTIGATING, note="Analyst assigned")
        assert rec.status == IncidentStatus.INVESTIGATING

    def test_valid_transition_chain(self):
        rec = self._make_record("INC-CHAIN01")
        rec.transition_to(IncidentStatus.INVESTIGATING)
        rec.transition_to(IncidentStatus.AWAITING_APPROVAL)
        rec.transition_to(IncidentStatus.CONTAINMENT_PENDING)
        assert rec.status == IncidentStatus.CONTAINMENT_PENDING

    def test_invalid_transition_raises(self):
        """Jumping from OPEN directly to RESOLVED is invalid."""
        rec = self._make_record("INC-INVALID01")
        with pytest.raises(IncidentTransitionError):
            rec.transition_to(IncidentStatus.RESOLVED)

    def test_transition_from_terminal_raises(self):
        """RESOLVED → OPEN must raise."""
        rec = self._make_record("INC-TERM01")
        rec.status = IncidentStatus.RESOLVED
        with pytest.raises(IncidentTransitionError):
            rec.transition_to(IncidentStatus.OPEN)

    def test_status_history_recorded(self):
        rec = self._make_record("INC-HIST01")
        rec.transition_to(IncidentStatus.INVESTIGATING, note="Test note")
        assert len(rec.status_history) == 1
        assert rec.status_history[0]["from"] == "OPEN"
        assert rec.status_history[0]["to"] == "INVESTIGATING"
        assert rec.status_history[0]["note"] == "Test note"

    def test_add_note(self):
        rec = self._make_record("INC-NOTE01")
        rec.add_note("Confirmed malicious activity")
        assert len(rec.analyst_notes) == 1
        assert "Confirmed malicious activity" in rec.analyst_notes[0]

    def test_priority_queue_sorted_by_score(self):
        mgr = IncidentManager()
        for i, score in enumerate([10.0, 90.0, 50.0]):
            rec = self._make_record(f"INC-PQ000{i}", score=score)
            mgr._records[rec.incident_id] = rec
        queue = mgr.get_priority_queue()
        scores = [r.risk_score for r in queue]
        assert scores == sorted(scores, reverse=True)

    def test_status_filter_works(self):
        mgr = IncidentManager()
        rec1 = self._make_record("INC-SF0001", score=80.0)
        rec2 = self._make_record("INC-SF0002", score=60.0)
        rec2.status = IncidentStatus.INVESTIGATING
        mgr._records[rec1.incident_id] = rec1
        mgr._records[rec2.incident_id] = rec2
        open_queue = mgr.get_priority_queue(status_filter=[IncidentStatus.OPEN])
        assert all(r.status == IncidentStatus.OPEN for r in open_queue)
        assert len(open_queue) == 1

    def test_count_by_status(self):
        mgr = IncidentManager()
        rec1 = self._make_record("INC-CBS01")
        rec2 = self._make_record("INC-CBS02")
        rec2.status = IncidentStatus.FALSE_POSITIVE
        mgr._records[rec1.incident_id] = rec1
        mgr._records[rec2.incident_id] = rec2
        counts = mgr.count_by_status()
        assert counts["OPEN"] == 1
        assert counts["FALSE_POSITIVE"] == 1

    def test_summary_dataframe_columns(self):
        mgr = IncidentManager()
        rec = self._make_record("INC-SDF01")
        mgr._records[rec.incident_id] = rec
        df = mgr.summary_dataframe()
        assert "incident_id" in df.columns
        assert "risk_score" in df.columns
        assert "status" in df.columns

    def test_get_unknown_id_raises(self):
        mgr = IncidentManager()
        with pytest.raises(KeyError):
            mgr.get("INC-DOESNOTEXIST")

    def test_phase2_no_contained_or_resolved_set(self):
        """Phase 2 must not auto-set CONTAINED or RESOLVED — only analyst can."""
        if not os.path.exists(DATASET_PATH):
            pytest.skip("Dataset not found.")
        df = load_events(DATASET_PATH)
        dets = detect_all(df)
        incidents = correlate(dets)
        scores = score_all(incidents)
        mgr = IncidentManager()
        mgr.load_incidents(incidents, scores)
        for rec in mgr.list_all():
            assert rec.status not in (IncidentStatus.CONTAINED, IncidentStatus.RESOLVED)
