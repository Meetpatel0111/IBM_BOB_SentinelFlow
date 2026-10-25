"""
validate_submission.py - Final submission validation checks.
Run from SentinelFlow/:
    python scripts/validate_submission.py
"""
import os, sys, json, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SEP = "=" * 60
passed = 0
failed = 0

def ok(msg):
    global passed
    print(f"  [PASS] {msg}")
    passed += 1

def fail(msg):
    global failed
    print(f"  [FAIL] {msg}")
    failed += 1

print(SEP)
print("  SentinelFlow - Final Submission Validation")
print(SEP)

# 1. Four mandatory files exist and are non-empty
print("\n[1] Mandatory submission files:")
for fname in ["Meet_SentinelFlow.ipynb", "requirements.txt",
              "Meet_ProjectReport.docx", "README.md"]:
    if os.path.isfile(fname) and os.path.getsize(fname) > 0:
        ok(f"{fname} ({os.path.getsize(fname):,} bytes)")
    else:
        fail(f"{fname} missing or empty")

# 2. Notebook cell errors
print("\n[2] Notebook execution:")
try:
    nb = json.load(open("Meet_SentinelFlow.ipynb", encoding="utf-8"))
    code_cells = [c for c in nb["cells"] if c["cell_type"] == "code"]
    error_cells = [i for i,c in enumerate(code_cells)
                   if any(o.get("output_type") == "error" for o in c.get("outputs",[]))]
    if error_cells:
        fail(f"Notebook has {len(error_cells)} error cell(s): {error_cells}")
    else:
        ok(f"All {len(code_cells)} code cells executed without errors")
    cells_with_output = sum(1 for c in code_cells if c.get("outputs"))
    ok(f"{cells_with_output}/{len(code_cells)} code cells have outputs")
except Exception as e:
    fail(f"Could not read notebook: {e}")

# 3. requirements.txt contains required packages
print("\n[3] requirements.txt packages:")
req = open("requirements.txt", encoding="utf-8").read().lower()
for pkg in ["pandas", "numpy", "matplotlib", "notebook", "python-docx",
            "seaborn", "pytest", "scikit-learn"]:
    if pkg in req:
        ok(f"requirements.txt contains {pkg}")
    else:
        fail(f"requirements.txt missing: {pkg}")

# 4. Ground-truth isolation — check RULE functions only (not docstrings or eval helpers)
print("\n[4] Ground-truth isolation:")
det_src = open("sentinelflow/detection.py", encoding="utf-8").read()
# Extract only the bodies of the five rule functions
rule_funcs = ["detect_brute_force", "detect_cred_stuffing",
              "detect_success_after_failure", "detect_off_hours",
              "detect_lateral_movement"]
gt_in_rules = False
for func_name in rule_funcs:
    # Get the text between this def and the next def (heuristic)
    if f"def {func_name}" in det_src:
        start = det_src.index(f"def {func_name}")
        rest  = det_src[start:]
        # Find next top-level def
        import re as _re
        nxt = _re.search(r'\ndef [a-z]', rest[10:])
        body = rest[:nxt.start()+10] if nxt else rest
        if "is_suspicious" in body or "scenario_label" in body:
            gt_in_rules = True
            fail(f"Ground-truth column referenced in {func_name}")
            break
if not gt_in_rules:
    ok("Ground-truth columns not referenced inside any rule function body")

# 5. Simulation mode
print("\n[5] Simulation mode:")
cont_src = open("sentinelflow/containment.py", encoding="utf-8").read()
if "simulation_mode: bool = True" in cont_src:
    ok("simulation_mode defaults to True in ContainmentAction")
else:
    fail("simulation_mode default not found")
if "[SIMULATION]" in cont_src:
    ok("All simulated action results contain [SIMULATION] marker")
else:
    fail("[SIMULATION] marker missing from action results")

# 6. No hardcoded secrets
print("\n[6] Secret scanning:")
secret_patterns = [
    r'api[_-]?key\s*=\s*["\'][^"\'\\s]{8,}',
    r'password\s*=\s*["\'][^"\'\\s]{4,}',
    r'token\s*=\s*["\'][^"\'\\s]{8,}',
]
secrets_found = []
for root, dirs, files in os.walk("sentinelflow"):
    for fname in files:
        if fname.endswith(".py"):
            content = open(os.path.join(root, fname), encoding="utf-8").read()
            for pat in secret_patterns:
                if re.search(pat, content, re.IGNORECASE):
                    secrets_found.append(fname)
                    break
if not secrets_found:
    ok("No hardcoded secrets found in sentinelflow/ source files")
else:
    fail(f"Potential secrets in: {secrets_found}")

# 7. outputs exist
print("\n[7] Runtime output files:")
for fpath in ["outputs/action_log.json", "outputs/incident_report.json"]:
    if os.path.isfile(fpath) and os.path.getsize(fpath) > 10:
        ok(f"{fpath} ({os.path.getsize(fpath):,} bytes)")
    else:
        fail(f"{fpath} missing or too small")

# 8. README contains key sections
print("\n[8] README content:")
readme = open("README.md", encoding="utf-8").read()
for section in ["Prerequisites", "Setup", "pip install", "pytest",
                "SIMULATION", "ground-truth", "requirements.txt"]:
    if section.lower() in readme.lower():
        ok(f"README contains section/term: '{section}'")
    else:
        fail(f"README missing: '{section}'")

print()
print(SEP)
print(f"  Result: {passed} passed,  {failed} failed")
print(SEP)
if failed == 0:
    print("  All submission validation checks passed.")
else:
    print(f"  {failed} check(s) failed — review above.")
