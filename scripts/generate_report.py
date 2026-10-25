"""
generate_report.py - Generate Meet_ProjectReport.docx from live pipeline results.
Run from the SentinelFlow/ directory:
    python scripts/generate_report.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.makedirs("outputs", exist_ok=True)

from sentinelflow.ingestion import load_events
from sentinelflow.detection import detect_all, attach_ground_truth, evaluate_detections
from sentinelflow.correlation import correlate
from sentinelflow.scoring import score_all
from sentinelflow.incidents import IncidentManager, IncidentStatus
from sentinelflow.containment import (
    execute_containment, recommend_action, load_action_log, ActionStatus
)
from sentinelflow.verification import verify_containment
from sentinelflow.reporting import build_report_data, save_report_json, generate_docx

LOG_PATH   = "outputs/action_log.json"
DOCX_PATH  = "Meet_ProjectReport.docx"
JSON_PATH  = "outputs/incident_report.json"
DATA_PATH  = "data/synthetic_auth_logs.csv"

print("[1/7] Loading dataset ...")
df = load_events(DATA_PATH)

print("[2/7] Running detection ...")
detections = detect_all(df)
detections = attach_ground_truth(list(detections), df)
metrics    = evaluate_detections(detections, df)

print("[3/7] Correlating incidents ...")
incidents = correlate(detections)
scores    = score_all(incidents)
manager   = IncidentManager()
manager.load_incidents(incidents, scores)

print("[4/7] Running demo containment + verification ...")
# Clear the action log so each report run starts fresh
if os.path.isfile(LOG_PATH):
    os.remove(LOG_PATH)

queue = manager.get_priority_queue(status_filter=[IncidentStatus.OPEN])
top   = queue[0]

try:
    manager.transition(top.incident_id, IncidentStatus.INVESTIGATING,
                       note="Report generation: demo containment")
    manager.transition(top.incident_id, IncidentStatus.AWAITING_APPROVAL,
                       note="Analyst approved for report demo")
except Exception:
    pass

action_type, target = recommend_action(top)
action = execute_containment(top, action_type, target, approved=True, log_path=LOG_PATH)
ver_results = verify_containment(top, log_path=LOG_PATH)

all_actions = load_action_log(LOG_PATH)
all_ver     = {top.incident_id: ver_results}

print("[5/7] Building report data ...")
report_data = build_report_data(
    df_events=df, detections=detections, incidents=incidents,
    scores=scores, manager=manager, eval_metrics=metrics,
    actions=all_actions, verifications=all_ver,
)

print("[6/7] Saving incident_report.json ...")
save_report_json(report_data, path=JSON_PATH)

print("[7/7] Generating Meet_ProjectReport.docx ...")
docx_abs = generate_docx(report_data, output_path=DOCX_PATH)
print(f"\nDone. Report saved to: {docx_abs}")
print(f"Size: {os.path.getsize(docx_abs):,} bytes")
