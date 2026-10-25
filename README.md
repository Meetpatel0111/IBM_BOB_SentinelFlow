# SentinelFlow

**Real-Time Detection and Automated Containment of Suspicious Account Activity Using Python-Based SIEM Workflows**

> **IBM SkillsBuild Cyber Security 2026 — BharatCares**
> Author: Riddhi Patel · Python 3.13.7 · Windows 10 x64

---

## Overview

SentinelFlow is a Blue Team cybersecurity project that implements a complete Python-based SIEM detection-to-response pipeline. It detects suspicious authentication activity in structured log data, correlates related findings into prioritised incidents, simulates containment actions with approval gating, and verifies the simulated response outcome.

**All containment actions are simulated. No real accounts, firewalls, or endpoints are modified.**

---

## Real-World Problem Being Solved

Enterprise authentication systems generate thousands of events per day. Manual triage cannot detect attack patterns such as brute force, credential stuffing, account takeover, off-hours access, and lateral movement at scale. SentinelFlow automates this detection and provides an explainable, auditable incident management workflow.

---

## Main Features

| Feature | Description |
|---|---|
| Synthetic dataset generation | Reproducible 4,953-event authentication log (seed=42) |
| 5 detection rules | Brute force · Credential stuffing · Success-after-failure · Off-hours · Lateral movement |
| Event correlation | Window-based grouping into named incidents |
| Explainable risk scoring | Transparent weighted 0–100 formula (documented) |
| Incident lifecycle | State machine: OPEN → INVESTIGATING → AWAITING_APPROVAL → CONTAINMENT_PENDING → CONTAINED → RESOLVED |
| Containment simulation | LOCK_ACCOUNT · BLOCK_IP · ISOLATE_HOST (all simulated, logged to JSON) |
| Post-action verification | Checks action log state; transitions to CONTAINED only on confirmed simulation |
| Automated test suite | 109 tests across all modules (107 pass, 2 skip until files exist) |
| Evaluation metrics | Precision=1.000 · Recall=0.969 · F1=0.984 · FPR=0.000 |
| Professional report | Auto-generated `Meet_ProjectReport.docx` from live results |

---

## Architecture

```
synthetic_auth_logs.csv
        │
        ▼
[ingestion.py]    — Schema validation, UTC timestamp normalisation
        │
        ▼
[detection.py]    — 5 rule-based detection functions (no ground truth used)
        │
        ▼
[correlation.py]  — Window-based grouping → Incident objects
        │
        ▼
[scoring.py]      — Weighted 0–100 risk score (documented formula)
        │
        ▼
[incidents.py]    — IncidentManager: lifecycle, state machine, queue
        │
        ▼
[containment.py]  — Approval-gated simulated actions + JSON log
        │
        ▼
[verification.py] — Checks action log state; transitions to CONTAINED
        │
        ▼
[reporting.py]    — JSON incident report + Meet_ProjectReport.docx
```

---

## Technologies Used

| Package | Version | Purpose |
|---|---|---|
| Python | 3.13.7 | Runtime |
| pandas | 2.3.3 | Data processing |
| numpy | 2.4.0 | Numerical operations |
| matplotlib | 3.10.8 | Charts and visualisations |
| seaborn | 0.13.2 | Statistical charts |
| scikit-learn | 1.8.0 | Evaluation metrics support |
| scipy | 1.16.3 | Statistical utilities |
| notebook | 7.6.3 | Jupyter notebook server |
| nbformat | 5.11.1 | Notebook file format |
| nbconvert | 7.17.2 | Notebook export and execution |
| nbclient | 0.11.0 | Headless notebook execution |
| python-docx | 1.2.0 | DOCX report generation |
| tabulate | 0.10.0 | Table formatting |
| requests | 2.32.5 | HTTP utilities (optional integrations) |
| colorama | 0.4.6 | Terminal colour output |
| pytest | 9.1.1 | Test runner |

---

## Project Folder Structure

```
SentinelFlow/
├── Meet_SentinelFlow.ipynb       ← Submission file 1 (Jupyter notebook)
├── requirements.txt              ← Submission file 2 (dependencies)
├── Meet_ProjectReport.docx       ← Submission file 3 (Word report)
├── README.md                     ← Submission file 4 (this file)
│
├── .env.example                  ← Optional integration env vars template
│
├── sentinelflow/                 ← Core Python package
│   ├── __init__.py
│   ├── generate_dataset.py       — Synthetic data generator
│   ├── ingestion.py              — CSV loader and validator
│   ├── detection.py              — 5 detection rules + evaluation helpers
│   ├── correlation.py            — Detection→Incident grouping
│   ├── scoring.py                — Risk score calculator
│   ├── incidents.py              — Incident lifecycle manager
│   ├── containment.py            — Simulated response engine
│   ├── verification.py           — Post-action verification
│   └── reporting.py              — JSON + DOCX report generation
│
├── data/
│   └── synthetic_auth_logs.csv   — Generated dataset (4,953 events, seed=42)
│
├── tests/
│   ├── test_phase2.py            — 69 unit tests (ingestion, detection, correlation, scoring, incidents)
│   └── test_phase3.py            — 40 unit tests (containment, verification, reporting, E2E)
│
├── scripts/
│   ├── build_notebook.py         — Generates Meet_SentinelFlow.ipynb
│   ├── evaluate.py               — Standalone evaluation script
│   ├── generate_report.py        — Generates Meet_ProjectReport.docx
│
└── outputs/                      ← Created at runtime
    ├── action_log.json
    ├── incident_report.json
    └── figures/
        ├── eda_overview.png
        ├── risk_score_distribution.png
        ├── incident_analysis.png
        └── event_timeline.png
```

---

## Dataset

**Name:** SentinelFlow Synthetic Authentication Log
**Source:** Generated by `sentinelflow/generate_dataset.py` — fully synthetic, no real enterprise data
**Reference schema:** LANL Comprehensive Multi-Source Cyber-Security Events Dataset — https://csr.lanl.gov/data/cyber1/
**Seed:** 42 (deterministic, reproducible)
**Size:** 4,953 events over 7 days (2025-07-08 to 2025-07-14, UTC)

| Scenario | Events | % |
|---|---|---|
| benign | 4,500 | 90.9% |
| brute_force | 181 | 3.7% |
| cred_stuffing | 140 | 2.8% |
| off_hours_access | 80 | 1.6% |
| lateral_movement | 52 | 1.0% |

> The `scenario_label` and `is_suspicious` columns are ground-truth labels used **only for post-hoc evaluation**. They are never read inside detection rule functions.

---

## Prerequisites

- **Python 3.13.7** (tested; 3.10+ should work)
- **Windows 10 x64** (tested; Linux/macOS compatible with path adjustments)
- **pip 25.3+**

---

## Setup Instructions (Windows PowerShell)

### 1. Navigate to the project directory

```powershell
cd "C:\Users\<YourUsername>\IBM Bob\IBM_Bob_Project\SentinelFlow"
```

### 2. Create and activate a virtual environment (recommended)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

> If you get a script execution error, run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

### 3. Install all dependencies

```powershell
pip install -r requirements.txt
```

### 4. Generate the synthetic dataset (already committed — run only if regenerating)

```powershell
python -m sentinelflow.generate_dataset
```

---

## Running the Project

### Launch the Jupyter Notebook

```powershell
python -m jupyter notebook Meet_SentinelFlow.ipynb
```

Then select **Kernel → Restart & Run All** to execute all cells from beginning to end.

### Run all automated tests

```powershell
python -m pytest tests/ -v
```

Expected result: **107 passed, 2 skipped** (the 2 skipped tests are guarded and pass once all submission files exist).

### Run standalone evaluation

```powershell
python scripts/evaluate.py
```

### Regenerate the Word report

```powershell
python scripts/generate_report.py
```

### Rebuild the notebook from source

```powershell
python scripts/build_notebook.py
python -m jupyter nbconvert --to notebook --execute --inplace Meet_SentinelFlow.ipynb
```

---

## Expected Outputs

After running the notebook end-to-end:

| Output | Location |
|---|---|
| Executed notebook with all outputs | `Meet_SentinelFlow.ipynb` |
| Incident action log (JSON) | `outputs/action_log.json` |
| Full incident report (JSON) | `outputs/incident_report.json` |
| EDA overview chart | `outputs/figures/eda_overview.png` |
| Risk score distribution | `outputs/figures/risk_score_distribution.png` |
| Incident analysis charts | `outputs/figures/incident_analysis.png` |
| Detection timeline | `outputs/figures/event_timeline.png` |

---

## Detection Rules Summary

| Rule | Name | Severity | Trigger Condition |
|---|---|---|---|
| RULE-BF | Brute Force | HIGH | ≥5 failures for same (user, source_ip) within 5 min |
| RULE-CS | Credential Stuffing | HIGH | ≥5 distinct accounts targeted from one IP within 10 min |
| RULE-SF | Success After Failure | CRITICAL | ≥3 failures then 1 success (same user+source) within 10 min |
| RULE-OH | Off-Hours Access | MEDIUM | Successful login outside 06:00–22:00 UTC |
| RULE-LM | Lateral Movement | HIGH | 1 account accessing ≥3 distinct hosts within 15 min |

All thresholds are configurable via keyword arguments to each rule function.

---

## Risk Scoring Formula

```
score = 0.35 * severity_score    +
        0.20 * diversity_score   +
        0.20 * sequence_score    +
        0.15 * host_spread_score +
        0.10 * recency_score
```

- **Severity:** CRITICAL=100, HIGH=75, MEDIUM=50
- **Diversity:** distinct rule types / 5
- **Sequence:** rewards SF→BF/CS→LM kill-chain pattern
- **Host spread:** distinct affected hosts / 7
- **Recency:** linear decay from 100 (< 1 h) to 0 (> 48 h)

---

## Incident Lifecycle

```
OPEN → INVESTIGATING → AWAITING_APPROVAL → CONTAINMENT_PENDING → CONTAINED → RESOLVED
     ↘ FALSE_POSITIVE (from any pre-terminal state)
```

Invalid transitions raise `IncidentTransitionError`. The engine does not auto-resolve incidents.

---

## Containment and Verification

Supported simulated actions:
- `LOCK_ACCOUNT` — Simulates disabling an AD account
- `BLOCK_IP` — Simulates adding an IP to a firewall deny list
- `ISOLATE_HOST` — Simulates network quarantine of a host

Every action requires `approved=True` to execute. All results are written to `outputs/action_log.json`. The verification engine reads this file and checks the result string for an expected simulation marker before transitioning the incident to `CONTAINED`.

---

## Optional Integrations (Not Required)

| Integration | Status | Notes |
|---|---|---|
| Wazuh XDR/SIEM | Optional | Set `WAZUH_API_URL` in `.env`; not connected in this project |
| Shuffle SOAR | Optional | Set `SHUFFLE_WEBHOOK_URL` in `.env`; not connected in this project |
| AbuseIPDB | Optional | Set `ABUSEIPDB_KEY` in `.env`; not connected in this project |

The project runs fully in simulation mode without any of these set.

---

## Evaluation Results (seed=42, 4,953 events)

| Metric | Value |
|---|---|
| True Positives | 439 |
| False Positives | 0 |
| False Negatives | 14 |
| True Negatives | 4,500 |
| **Precision** | **1.0000** |
| **Recall** | **0.9691** |
| **F1-Score** | **0.9843** |
| **False Positive Rate** | **0.0000** |

> **Important:** Zero FP is partly an artefact of synthetic data calibration. In real environments, RULE-OH will generate FPs for legitimate off-hours remote workers.

---

## Security and Ethical Limitations

1. All data is synthetic — results may not generalise to real enterprise environments.
2. RULE-OH flags all off-hours logins including legitimate remote workers; tuning required per-organisation.
3. No ground-truth labels are used inside detection logic — confirmed by `test_ground_truth_not_used` test.
4. Simulation mode is always enabled — confirmed by `test_simulation_mode_always_true` test and `test_no_real_action_taken` test.
5. This system must not be deployed in a real environment without thorough validation, tuning, and human oversight.
6. No credentials, secrets, or personal access tokens are committed to this repository.

---

## Future Enhancements

- MITRE ATT&CK tactic tagging on each detection
- Wazuh REST API integration for live log ingestion
- Shuffle SOAR webhook for automated response dispatch
- Sliding-window streaming pipeline (Kafka / Redis Streams)
- ML-based anomaly scoring as a complementary layer
- Impossible-travel detection using IP geolocation

---

## References

1. Turcotte, M. J. F., et al. (2014). Unified Host and Network Data Set. LANL. https://csr.lanl.gov/data/cyber1/
2. MITRE ATT&CK Framework. https://attack.mitre.org/
3. Wazuh Open Source XDR and SIEM. https://wazuh.com/
4. Shuffle SOAR Platform. https://shuffler.io/
5. IBM SkillsBuild. https://skillsbuild.org/

---

## Submission File Locations

| File | Path |
|---|---|
| Notebook | `SentinelFlow/Meet_SentinelFlow.ipynb` |
| Dependencies | `SentinelFlow/requirements.txt` |
| Word Report | `SentinelFlow/Meet_ProjectReport.docx` |
| README | `SentinelFlow/README.md` |
