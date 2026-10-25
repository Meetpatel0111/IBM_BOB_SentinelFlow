"""
SentinelFlow - tests/test_phase3.py
=====================================
Additional tests for Phase B modules: containment, verification, reporting.
Also includes end-to-end integration tests and submission-file validation.

Run with:
    cd SentinelFlow
    python -m pytest tests/ -v
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import shutil

import pandas as pd
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sentinelflow.ingestion import load_events
from sentinelflow.detection import detect_all, attach_ground_truth, evaluate_detections
from sentinelflow.correlation import correlate, Incident
from sentinelflow.scoring import score_all
from sentinelflow.incidents import (
    IncidentManager, IncidentRecord, IncidentStatus, IncidentTransitionError
)
from sentinelflow.containment import (
    execute_containment, recommend_action, load_action_log,
    get_actions_for_incident, ActionStatus, VALID_ACTION_TYPES,
)
from sentinelflow.verification import (
    verify_containment, VerificationOutcome,
)
from sentinelflow.reporting import build_report_data, save_report_json, generate_docx

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "synthetic_auth_logs.csv")
_TS_BASE = pd.Timestamp("2025-07-10T09:00:00Z")


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _make_incident_record(
    inc_id: str = "INC-TEST0001",
    score: float = 70.0,
    detection_types: list | None = None,
    severities: list | None = None,
    username: str = "alice.morgan",
    source_ip: str = "185.220.101.45",
    affected_hosts: list | None = None,
) -> IncidentRecord:
    inc = Incident(
        incident_id=inc_id,
        username=username,
        source_ip=source_ip,
        affected_hosts=affected_hosts or ["DC-CORP01"],
        detection_ids=["DET-ZZZZZ001"],
        supporting_event_ids=["EVT-ZZZZ0001"],
        detection_types=detection_types or ["RULE-BF"],
        severities=severities or ["HIGH"],
        incident_start=_TS_BASE,
        incident_last_seen=_TS_BASE,
        detection_count=1,
        event_count=1,
    )
    return IncidentRecord(incident=inc, risk_score=score)


def _tmp_log(tmp_path) -> str:
    return str(tmp_path / "action_log.json")


# ============================================================================
# Phase B1: containment.py
# ============================================================================

class TestContainmentRecommendation:

    def test_recommend_lock_account_for_bf(self):
        rec = _make_incident_record(detection_types=["RULE-BF"])
        action_type, target = recommend_action(rec)
        assert action_type == "LOCK_ACCOUNT"
        assert target == rec.incident.username

    def test_recommend_block_ip_for_cs(self):
        rec = _make_incident_record(detection_types=["RULE-CS"])
        action_type, target = recommend_action(rec)
        assert action_type == "BLOCK_IP"
        assert target == rec.incident.source_ip

    def test_recommend_isolate_host_for_lm(self):
        rec = _make_incident_record(detection_types=["RULE-LM"],
                                     affected_hosts=["SRV-A", "SRV-B"])
        action_type, target = recommend_action(rec)
        assert action_type == "ISOLATE_HOST"
        assert target == "SRV-A"

    def test_lm_takes_priority_over_bf(self):
        """RULE-LM has highest priority in the recommendation logic."""
        rec = _make_incident_record(detection_types=["RULE-BF", "RULE-LM"],
                                     affected_hosts=["SRV-A"])
        action_type, _ = recommend_action(rec)
        assert action_type == "ISOLATE_HOST"


class TestContainmentExecution:

    def test_approved_lock_account_succeeds(self, tmp_path):
        rec = _make_incident_record()
        # Advance to AWAITING_APPROVAL
        rec.transition_to(IncidentStatus.INVESTIGATING)
        rec.transition_to(IncidentStatus.AWAITING_APPROVAL)
        action = execute_containment(
            rec, "LOCK_ACCOUNT", "alice.morgan", approved=True,
            log_path=_tmp_log(tmp_path)
        )
        assert action.status == ActionStatus.EXECUTED
        assert action.approved is True
        assert "DISABLED" in action.result

    def test_approved_block_ip_succeeds(self, tmp_path):
        rec = _make_incident_record(inc_id="INC-BIP0001")
        rec.transition_to(IncidentStatus.INVESTIGATING)
        rec.transition_to(IncidentStatus.AWAITING_APPROVAL)
        action = execute_containment(
            rec, "BLOCK_IP", "185.220.101.45", approved=True,
            log_path=_tmp_log(tmp_path)
        )
        assert action.status == ActionStatus.EXECUTED
        assert "deny list" in action.result

    def test_approved_isolate_host_succeeds(self, tmp_path):
        rec = _make_incident_record(inc_id="INC-ISO0001")
        rec.transition_to(IncidentStatus.INVESTIGATING)
        rec.transition_to(IncidentStatus.AWAITING_APPROVAL)
        action = execute_containment(
            rec, "ISOLATE_HOST", "SRV-FILESERVER01", approved=True,
            log_path=_tmp_log(tmp_path)
        )
        assert action.status == ActionStatus.EXECUTED
        assert "quarantine" in action.result.lower()

    def test_rejected_action_not_executed(self, tmp_path):
        rec = _make_incident_record(inc_id="INC-REJ0001")
        action = execute_containment(
            rec, "LOCK_ACCOUNT", "alice.morgan", approved=False,
            log_path=_tmp_log(tmp_path)
        )
        assert action.status == ActionStatus.REJECTED
        assert action.result is None

    def test_simulate_failure(self, tmp_path):
        rec = _make_incident_record(inc_id="INC-FAIL001")
        rec.transition_to(IncidentStatus.INVESTIGATING)
        rec.transition_to(IncidentStatus.AWAITING_APPROVAL)
        action = execute_containment(
            rec, "LOCK_ACCOUNT", "alice.morgan", approved=True,
            simulate_failure=True, log_path=_tmp_log(tmp_path)
        )
        assert action.status == ActionStatus.FAILED
        assert "FAILED" in action.result

    def test_duplicate_executed_raises(self, tmp_path):
        """Submitting the same (incident, action_type, target) twice raises."""
        rec = _make_incident_record(inc_id="INC-DUP0001")
        rec.transition_to(IncidentStatus.INVESTIGATING)
        rec.transition_to(IncidentStatus.AWAITING_APPROVAL)
        log = _tmp_log(tmp_path)
        execute_containment(rec, "LOCK_ACCOUNT", "alice.morgan", approved=True, log_path=log)
        # Reset status to allow re-attempt
        with pytest.raises(ValueError, match="already been EXECUTED"):
            execute_containment(rec, "LOCK_ACCOUNT", "alice.morgan", approved=True, log_path=log)

    def test_invalid_action_type_raises(self, tmp_path):
        rec = _make_incident_record(inc_id="INC-INV0001")
        with pytest.raises(ValueError, match="Unknown action_type"):
            execute_containment(rec, "DELETE_USER", "alice", approved=True,
                                log_path=_tmp_log(tmp_path))

    def test_simulation_mode_always_true(self, tmp_path):
        """simulation_mode field must always be True."""
        rec = _make_incident_record(inc_id="INC-SIM0001")
        action = execute_containment(
            rec, "LOCK_ACCOUNT", "alice.morgan", approved=False,
            log_path=_tmp_log(tmp_path)
        )
        assert action.simulation_mode is True

    def test_action_persisted_to_log(self, tmp_path):
        """The action must be written to the JSON log file."""
        log = _tmp_log(tmp_path)
        rec = _make_incident_record(inc_id="INC-LOG0001")
        execute_containment(rec, "LOCK_ACCOUNT", "alice.morgan", approved=True, log_path=log)
        actions = load_action_log(log)
        assert len(actions) == 1
        assert actions[0].incident_id == "INC-LOG0001"

    def test_get_actions_for_incident(self, tmp_path):
        log = _tmp_log(tmp_path)
        rec1 = _make_incident_record(inc_id="INC-GA00001")
        rec2 = _make_incident_record(inc_id="INC-GA00002")
        execute_containment(rec1, "LOCK_ACCOUNT", "alice.morgan", approved=True, log_path=log)
        execute_containment(rec2, "BLOCK_IP", "9.9.9.9", approved=True, log_path=log)
        actions = get_actions_for_incident("INC-GA00001", log_path=log)
        assert len(actions) == 1
        assert actions[0].incident_id == "INC-GA00001"

    def test_incident_advances_to_containment_pending_on_execute(self, tmp_path):
        rec = _make_incident_record(inc_id="INC-CP00001")
        rec.transition_to(IncidentStatus.INVESTIGATING)
        rec.transition_to(IncidentStatus.AWAITING_APPROVAL)
        execute_containment(rec, "LOCK_ACCOUNT", "alice.morgan", approved=True,
                            log_path=_tmp_log(tmp_path))
        assert rec.status == IncidentStatus.CONTAINMENT_PENDING


# ============================================================================
# Phase B2: verification.py
# ============================================================================

class TestVerification:

    def test_success_verification_on_executed_action(self, tmp_path):
        log = _tmp_log(tmp_path)
        rec = _make_incident_record(inc_id="INC-VER0001")
        rec.transition_to(IncidentStatus.INVESTIGATING)
        rec.transition_to(IncidentStatus.AWAITING_APPROVAL)
        execute_containment(rec, "LOCK_ACCOUNT", "alice.morgan", approved=True, log_path=log)
        results = verify_containment(rec, log_path=log)
        assert len(results) == 1
        assert results[0].outcome == VerificationOutcome.SUCCESS
        assert results[0].follow_up_needed is False

    def test_failed_verification_on_failed_action(self, tmp_path):
        log = _tmp_log(tmp_path)
        rec = _make_incident_record(inc_id="INC-VER0002")
        rec.transition_to(IncidentStatus.INVESTIGATING)
        rec.transition_to(IncidentStatus.AWAITING_APPROVAL)
        execute_containment(rec, "LOCK_ACCOUNT", "alice.morgan", approved=True,
                            simulate_failure=True, log_path=log)
        results = verify_containment(rec, log_path=log)
        assert results[0].outcome == VerificationOutcome.FAILED
        assert results[0].follow_up_needed is True

    def test_unverified_when_no_action_exists(self, tmp_path):
        log = _tmp_log(tmp_path)
        rec = _make_incident_record(inc_id="INC-VER0003")
        results = verify_containment(rec, log_path=log)
        assert results[0].outcome == VerificationOutcome.UNVERIFIED

    def test_rejected_action_gives_unverified(self, tmp_path):
        log = _tmp_log(tmp_path)
        rec = _make_incident_record(inc_id="INC-VER0004")
        execute_containment(rec, "LOCK_ACCOUNT", "alice.morgan", approved=False, log_path=log)
        results = verify_containment(rec, log_path=log)
        assert results[0].outcome == VerificationOutcome.UNVERIFIED

    def test_success_transitions_incident_to_contained(self, tmp_path):
        log = _tmp_log(tmp_path)
        rec = _make_incident_record(inc_id="INC-VER0005")
        rec.transition_to(IncidentStatus.INVESTIGATING)
        rec.transition_to(IncidentStatus.AWAITING_APPROVAL)
        execute_containment(rec, "LOCK_ACCOUNT", "alice.morgan", approved=True, log_path=log)
        verify_containment(rec, log_path=log)
        assert rec.status == IncidentStatus.CONTAINED

    def test_failed_verification_does_not_resolve_incident(self, tmp_path):
        log = _tmp_log(tmp_path)
        rec = _make_incident_record(inc_id="INC-VER0006")
        rec.transition_to(IncidentStatus.INVESTIGATING)
        rec.transition_to(IncidentStatus.AWAITING_APPROVAL)
        execute_containment(rec, "LOCK_ACCOUNT", "alice.morgan", approved=True,
                            simulate_failure=True, log_path=log)
        verify_containment(rec, log_path=log)
        # Incident should NOT be CONTAINED or RESOLVED
        assert rec.status not in (IncidentStatus.CONTAINED, IncidentStatus.RESOLVED)

    def test_verification_result_has_evidence(self, tmp_path):
        log = _tmp_log(tmp_path)
        rec = _make_incident_record(inc_id="INC-VER0007")
        rec.transition_to(IncidentStatus.INVESTIGATING)
        rec.transition_to(IncidentStatus.AWAITING_APPROVAL)
        execute_containment(rec, "BLOCK_IP", "9.9.9.9", approved=True, log_path=log)
        results = verify_containment(rec, log_path=log)
        assert results[0].evidence != ""
        assert len(results[0].evidence) > 10


# ============================================================================
# Phase B3: reporting.py
# ============================================================================

class TestReporting:

    def _build_minimal_report(self, tmp_path):
        """Shared helper to produce a minimal valid report_data dict."""
        log = str(tmp_path / "action_log.json")
        df = load_events(DATASET_PATH) if os.path.exists(DATASET_PATH) else None
        if df is None:
            pytest.skip("Dataset not found.")

        detections = detect_all(df)
        detections = attach_ground_truth(detections, df)
        incidents  = correlate(detections)
        scores     = score_all(incidents)
        manager    = IncidentManager()
        manager.load_incidents(incidents, scores)
        metrics    = evaluate_detections(detections, df)
        actions    = load_action_log(log)
        return build_report_data(
            df_events=df, detections=detections, incidents=incidents,
            scores=scores, manager=manager, eval_metrics=metrics,
            actions=actions, verifications={},
        )

    def test_report_data_has_required_keys(self, tmp_path):
        rd = self._build_minimal_report(tmp_path)
        for key in ["project", "dataset", "detection", "evaluation",
                    "incidents", "containment", "verification", "run_timestamp"]:
            assert key in rd, f"Missing key: {key}"

    def test_report_data_metrics_match_detection(self, tmp_path):
        rd = self._build_minimal_report(tmp_path)
        assert rd["evaluation"]["tp"] >= 0
        assert rd["evaluation"]["fp"] >= 0
        assert 0.0 <= rd["evaluation"]["precision"] <= 1.0

    def test_save_report_json(self, tmp_path):
        rd = self._build_minimal_report(tmp_path)
        path = str(tmp_path / "report.json")
        saved = save_report_json(rd, path=path)
        assert os.path.isfile(saved)
        with open(saved, encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded["project"]["author"] == "Riddhi Patel"

    def test_generate_docx(self, tmp_path):
        rd = self._build_minimal_report(tmp_path)
        docx_path = str(tmp_path / "TestReport.docx")
        result = generate_docx(rd, output_path=docx_path)
        assert os.path.isfile(result)
        assert os.path.getsize(result) > 5000   # non-trivial file

    def test_docx_contains_project_title(self, tmp_path):
        from docx import Document
        rd = self._build_minimal_report(tmp_path)
        docx_path = str(tmp_path / "TitleCheck.docx")
        generate_docx(rd, output_path=docx_path)
        doc = Document(docx_path)
        full_text = " ".join(p.text for p in doc.paragraphs)
        assert "SentinelFlow" in full_text
        assert "Riddhi Patel" in full_text

    def test_malformed_action_log_handled(self, tmp_path):
        """load_action_log on a corrupted file returns empty list."""
        bad_log = tmp_path / "bad.json"
        bad_log.write_text("not valid json {{{{")
        result = load_action_log(str(bad_log))
        assert result == []


# ============================================================================
# End-to-end integration tests
# ============================================================================

class TestEndToEnd:

    def test_full_pipeline_runs_without_error(self, tmp_path):
        """Full pipeline: load -> detect -> correlate -> score -> manage -> contain -> verify."""
        if not os.path.exists(DATASET_PATH):
            pytest.skip("Dataset not found.")

        log = _tmp_log(tmp_path)

        df = load_events(DATASET_PATH)
        detections = detect_all(df)
        incidents  = correlate(detections)
        scores     = score_all(incidents)
        manager    = IncidentManager()
        manager.load_incidents(incidents, scores)

        queue = manager.get_priority_queue(status_filter=[IncidentStatus.OPEN])
        assert len(queue) > 0

        # Full lifecycle on top incident
        top = queue[0]
        manager.transition(top.incident_id, IncidentStatus.INVESTIGATING)
        manager.transition(top.incident_id, IncidentStatus.AWAITING_APPROVAL)

        action_type, target = recommend_action(top)
        action = execute_containment(top, action_type, target, approved=True, log_path=log)
        assert action.status == ActionStatus.EXECUTED

        results = verify_containment(top, log_path=log)
        assert any(r.outcome == VerificationOutcome.SUCCESS for r in results)
        assert top.status == IncidentStatus.CONTAINED

    def test_ground_truth_not_used_in_pipeline(self, tmp_path):
        """Full pipeline succeeds even with ground-truth columns stripped."""
        if not os.path.exists(DATASET_PATH):
            pytest.skip("Dataset not found.")

        df = load_events(DATASET_PATH)
        df_no_gt = df.drop(columns=["scenario_label", "is_suspicious"], errors="ignore")

        detections = detect_all(df_no_gt)
        incidents  = correlate(detections)
        scores     = score_all(incidents)
        assert len(incidents) > 0

    def test_rejected_containment_does_not_advance_incident(self, tmp_path):
        """A REJECTED action must not change incident status."""
        log = _tmp_log(tmp_path)
        rec = _make_incident_record(inc_id="INC-E2E0001")
        initial_status = rec.status
        execute_containment(rec, "LOCK_ACCOUNT", "alice.morgan", approved=False, log_path=log)
        assert rec.status == initial_status

    def test_audit_log_consistency(self, tmp_path):
        """All persisted actions have required fields."""
        log = _tmp_log(tmp_path)
        rec1 = _make_incident_record(inc_id="INC-AUD0001")
        rec2 = _make_incident_record(inc_id="INC-AUD0002", source_ip="1.2.3.4")
        rec1.transition_to(IncidentStatus.INVESTIGATING)
        rec1.transition_to(IncidentStatus.AWAITING_APPROVAL)
        rec2.transition_to(IncidentStatus.INVESTIGATING)
        rec2.transition_to(IncidentStatus.AWAITING_APPROVAL)
        execute_containment(rec1, "LOCK_ACCOUNT", "alice.morgan", approved=True, log_path=log)
        execute_containment(rec2, "BLOCK_IP", "1.2.3.4", approved=False, log_path=log)
        actions = load_action_log(log)
        required_fields = [
            "action_id", "incident_id", "action_type", "target",
            "status", "approved", "created_at", "simulation_mode",
        ]
        for a in actions:
            for field in required_fields:
                assert getattr(a, field, None) is not None, f"Missing field: {field}"

    def test_no_real_action_taken(self, tmp_path):
        """Result string must contain [SIMULATION] marker — never real action text."""
        log = _tmp_log(tmp_path)
        rec = _make_incident_record(inc_id="INC-SIM9001")
        rec.transition_to(IncidentStatus.INVESTIGATING)
        rec.transition_to(IncidentStatus.AWAITING_APPROVAL)
        action = execute_containment(rec, "LOCK_ACCOUNT", "alice.morgan",
                                     approved=True, log_path=log)
        assert "[SIMULATION]" in action.result
        assert "[SIMULATION]" in action.explanation


# ============================================================================
# Submission file validation
# ============================================================================

class TestSubmissionFiles:
    """Verify the four mandatory submission files exist at project root."""

    ROOT = os.path.join(os.path.dirname(__file__), "..")

    def _check(self, filename):
        path = os.path.join(self.ROOT, filename)
        assert os.path.isfile(path), f"Mandatory submission file missing: {filename}"
        assert os.path.getsize(path) > 0, f"Submission file is empty: {filename}"

    def test_notebook_exists(self):
        self._check("Meet_SentinelFlow.ipynb")

    def test_requirements_exists(self):
        self._check("requirements.txt")

    def test_readme_exists(self):
        # README may not exist yet during Phase D; will exist by Phase G
        path = os.path.join(self.ROOT, "README.md")
        if not os.path.isfile(path):
            pytest.skip("README.md not yet created (Phase G).")
        assert os.path.getsize(path) > 100

    def test_docx_exists(self):
        # DOCX may not exist yet during Phase D; will exist by Phase F
        path = os.path.join(self.ROOT, "Meet_ProjectReport.docx")
        if not os.path.isfile(path):
            pytest.skip("Meet_ProjectReport.docx not yet created (Phase F).")
        assert os.path.getsize(path) > 1000

    def test_notebook_is_valid_json(self):
        import json as _json
        path = os.path.join(self.ROOT, "Meet_SentinelFlow.ipynb")
        if not os.path.isfile(path):
            pytest.skip("Notebook not yet created.")
        with open(path, encoding="utf-8") as f:
            nb = _json.load(f)
        assert "cells" in nb
        assert "metadata" in nb

    def test_notebook_cells_have_no_errors(self):
        """All executed cells in the notebook must have no error outputs."""
        import json as _json
        path = os.path.join(self.ROOT, "Meet_SentinelFlow.ipynb")
        if not os.path.isfile(path):
            pytest.skip("Notebook not yet created.")
        with open(path, encoding="utf-8") as f:
            nb = _json.load(f)
        error_cells = []
        for i, cell in enumerate(nb.get("cells", [])):
            if cell.get("cell_type") != "code":
                continue
            for output in cell.get("outputs", []):
                if output.get("output_type") == "error":
                    error_cells.append(i)
        assert error_cells == [], f"Notebook cells with errors: {error_cells}"

    def test_requirements_contains_core_packages(self):
        path = os.path.join(self.ROOT, "requirements.txt")
        content = open(path, encoding="utf-8").read().lower()
        for pkg in ["pandas", "numpy", "matplotlib", "notebook", "python-docx"]:
            assert pkg in content, f"requirements.txt missing: {pkg}"
