"""
SentinelFlow Phase 2 - Evaluation script
Run: python scripts/evaluate.py
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collections import Counter
from sentinelflow.ingestion import load_events
from sentinelflow.detection import detect_all, attach_ground_truth, evaluate_detections
from sentinelflow.correlation import correlate
from sentinelflow.scoring import score_all
from sentinelflow.incidents import IncidentManager

SEP = "=" * 65

print(SEP)
print("  SentinelFlow - Phase 2 Evaluation Report")
print(SEP)

# 1. Load dataset
df = load_events("data/synthetic_auth_logs.csv")
n_total   = len(df)
n_attack  = int(df["is_suspicious"].sum())
n_benign  = int((df["is_suspicious"] == 0).sum())
print(f"\nDataset  : {n_total:,} events")
print(f"Attack   : {n_attack:,}  ({n_attack/n_total*100:.1f} %)")
print(f"Benign   : {n_benign:,}  ({n_benign/n_total*100:.1f} %)")

# 2. Run detection (NO ground-truth columns used inside rules)
dets = detect_all(df)
print(f"\nDetections produced : {len(dets)}")

rule_counts = Counter(d.rule_id for d in dets)
for rule, count in sorted(rule_counts.items()):
    print(f"  {rule}: {count}")

# 3. Attach ground truth AFTER detection (evaluation only)
dets = attach_ground_truth(dets, df)

# 4. Event-level evaluation
metrics = evaluate_detections(dets, df)
print()
print("Event-level metrics (flagged event_ids vs ground-truth is_suspicious):")
print(f"  True Positives  (TP) : {metrics['tp']:>6}")
print(f"  False Positives (FP) : {metrics['fp']:>6}")
print(f"  False Negatives (FN) : {metrics['fn']:>6}")
print(f"  True Negatives  (TN) : {metrics['tn']:>6}")
print(f"  Precision             : {metrics['precision']:>6.4f}")
print(f"  Recall                : {metrics['recall']:>6.4f}")
print(f"  F1-Score              : {metrics['f1']:>6.4f}")
print(f"  False Positive Rate   : {metrics['fpr']:>6.4f}")

# 5. Correlate + score + incident manager
incidents = correlate(dets)
scores    = score_all(incidents)
mgr       = IncidentManager()
mgr.load_incidents(incidents, scores)

df_summary = mgr.summary_dataframe()
print()
print(f"Correlated incidents  : {len(incidents)}")
print(f"Status counts         : {mgr.count_by_status()}")

print()
print("Top 10 incidents by risk score:")
cols = ["incident_id", "risk_score", "max_severity", "detection_types",
        "username", "source_ip", "event_count"]
print(df_summary[cols].head(10).to_string(index=False))

# 6. Score distribution
print()
print("Risk score distribution:")
sc = df_summary["risk_score"]
for label, val in [
    ("Min",      sc.min()),
    ("25th pct", sc.quantile(0.25)),
    ("Median",   sc.median()),
    ("75th pct", sc.quantile(0.75)),
    ("Max",      sc.max()),
]:
    print(f"  {label:<12}: {val:.2f}")

print()
print(SEP)
