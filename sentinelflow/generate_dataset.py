"""
SentinelFlow - Synthetic Authentication Log Generator
======================================================
Generates a reproducible synthetic dataset of Windows-style authentication
events for SIEM detection research and development.

DISCLAIMER
----------
This dataset is entirely synthetic and does NOT represent real enterprise
data, real users, real IP addresses, or real hostnames. It is generated
programmatically using a fixed random seed for full reproducibility.
No real authentication events were collected or used.

The schema mirrors the LANL Comprehensive Multi-Source Cyber-Security Events
dataset (https://csr.lanl.gov/data/cyber1/) so that the detection engine
can be adapted to work with real LANL data by replacing the CSV source path.

Usage
-----
    python -m sentinelflow.generate_dataset            # saves to data/synthetic_auth_logs.csv
    python -m sentinelflow.generate_dataset --validate # generate + run schema validation
    python -m sentinelflow.generate_dataset --seed 99  # override random seed

    Or import programmatically:
        from sentinelflow.generate_dataset import generate_dataset
        df = generate_dataset(n_benign=4500, seed=42)

Dataset Schema
--------------
event_id         : str   — globally unique event identifier (EVT-XXXXXXXX)
timestamp        : str   — ISO-8601 UTC datetime (YYYY-MM-DDTHH:MM:SSZ)
username         : str   — simulated Active Directory samAccountName
source_ip        : str   — IPv4 address of the originating host
source_host      : str   — hostname of the originating workstation/server
destination_host : str   — hostname of the target server/domain controller
auth_type        : str   — Kerberos | NTLM | Negotiate
logon_type       : str   — Interactive | Network | RemoteInteractive
event_outcome    : str   — Success | Failure
scenario_label   : str   — benign | brute_force | cred_stuffing |
                           off_hours_access | lateral_movement
is_suspicious    : int   — ground-truth binary label (0 = benign, 1 = attack)
"""

from __future__ import annotations

import argparse
import os
import random
import sys
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Constants — edit these to adjust the simulation parameters
# ---------------------------------------------------------------------------

RANDOM_SEED: int = 42
N_BENIGN: int = 4500          # number of normal background events
OUTPUT_PATH: str = os.path.join(
    os.path.dirname(__file__), "..", "data", "synthetic_auth_logs.csv"
)

# Simulation window: 7 days ending at the generation timestamp (UTC)
SIM_END: datetime = datetime(2025, 7, 14, 23, 59, 59, tzinfo=timezone.utc)
SIM_START: datetime = SIM_END - timedelta(days=7)

# Business-hours definition (UTC) — logins outside this window are off-hours
BIZ_HOUR_START: int = 6   # 06:00 UTC
BIZ_HOUR_END: int = 22    # 22:00 UTC

# ---------------------------------------------------------------------------
# Simulated corporate topology
# ---------------------------------------------------------------------------

USERNAMES: list[str] = [
    "alice.morgan", "bob.kumar", "carol.zhang", "david.patel",
    "eve.santos", "frank.osei", "grace.lin", "henry.novak",
    "irene.wade", "james.okafor", "kate.bell", "liam.chen",
    "maya.roy", "noah.garcia", "olivia.kim", "peter.scott",
    "quinn.adams", "rachel.foster", "sam.nair", "tanya.white",
]

# Normal workstations — employees log in from their own machine
WORKSTATIONS: list[str] = [f"WS-{u.split('.')[0].upper()}" for u in USERNAMES]

# Servers that users legitimately reach
SERVERS: list[str] = [
    "SRV-FILESERVER01", "SRV-APPSERVER01", "SRV-DBSERVER01",
    "SRV-WEBSERVER01",  "SRV-MAILSERVER01",
]

# Domain controllers — Kerberos/NTLM authentication targets
DOMAIN_CONTROLLERS: list[str] = ["DC-CORP01", "DC-CORP02"]

# Attacker-controlled external IPs (used in brute_force / cred_stuffing)
ATTACKER_IPS: list[str] = [
    "185.220.101.45", "45.142.212.100", "91.108.4.18",
    "194.165.16.72",  "185.234.218.51",
]

# Internal IP pool — 10.10.x.x subnet
def _make_internal_ip(rng: random.Random) -> str:
    return f"10.10.{rng.randint(0, 9)}.{rng.randint(1, 254)}"

AUTH_TYPES: list[str] = ["Kerberos", "NTLM", "Negotiate"]
AUTH_WEIGHTS: list[float] = [0.60, 0.30, 0.10]

LOGON_TYPES: list[str] = ["Interactive", "Network", "RemoteInteractive"]
LOGON_WEIGHTS: list[float] = [0.50, 0.35, 0.15]

# ---------------------------------------------------------------------------
# Unique event ID generator
# ---------------------------------------------------------------------------

def _new_event_id(rng: random.Random, used: set[str]) -> str:
    """Return a unique EVT-XXXXXXXX identifier derived from the seeded RNG."""
    while True:
        raw = rng.getrandbits(32)
        eid = f"EVT-{raw:08X}"
        if eid not in used:
            used.add(eid)
            return eid

# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def _random_biz_ts(rng: random.Random) -> datetime:
    """Random timestamp inside business hours within the simulation window."""
    while True:
        offset = timedelta(seconds=rng.randint(0, int((SIM_END - SIM_START).total_seconds())))
        ts = SIM_START + offset
        if BIZ_HOUR_START <= ts.hour < BIZ_HOUR_END:
            return ts

def _random_offhours_ts(rng: random.Random) -> datetime:
    """Random timestamp strictly outside business hours."""
    while True:
        offset = timedelta(seconds=rng.randint(0, int((SIM_END - SIM_START).total_seconds())))
        ts = SIM_START + offset
        if ts.hour < BIZ_HOUR_START or ts.hour >= BIZ_HOUR_END:
            return ts

def _fmt(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")

# ---------------------------------------------------------------------------
# Scenario generators
# ---------------------------------------------------------------------------

def _benign_events(
    n: int, rng: random.Random, used_ids: set[str]
) -> list[dict]:
    """
    Normal business-hours authentication events.
    Each user logs in from their own workstation to a server or DC.
    Outcome is Success with ~96 % probability (occasional typos → Failure).
    """
    rows = []
    for _ in range(n):
        idx = rng.randrange(len(USERNAMES))
        user = USERNAMES[idx]
        ws   = WORKSTATIONS[idx]
        ip   = _make_internal_ip(rng)
        dest = rng.choice(SERVERS + DOMAIN_CONTROLLERS)
        ts   = _random_biz_ts(rng)
        outcome = "Success" if rng.random() < 0.96 else "Failure"
        rows.append({
            "event_id":         _new_event_id(rng, used_ids),
            "timestamp":        _fmt(ts),
            "username":         user,
            "source_ip":        ip,
            "source_host":      ws,
            "destination_host": dest,
            "auth_type":        rng.choices(AUTH_TYPES, AUTH_WEIGHTS)[0],
            "logon_type":       rng.choices(LOGON_TYPES, LOGON_WEIGHTS)[0],
            "event_outcome":    outcome,
            "scenario_label":   "benign",
            "is_suspicious":    0,
        })
    return rows


def _brute_force_events(
    n_attacks: int, rng: random.Random, used_ids: set[str]
) -> list[dict]:
    """
    Brute-force: an external IP sends rapid repeated Failure events against
    a single account, then optionally one Success at the end.
    Pattern: 8–15 Failures in a tight 3-minute window, then 0–1 Success.
    """
    rows = []
    for _ in range(n_attacks):
        target_user = rng.choice(USERNAMES)
        attacker_ip = rng.choice(ATTACKER_IPS)
        dc          = rng.choice(DOMAIN_CONTROLLERS)
        base_ts     = _random_biz_ts(rng)
        n_failures  = rng.randint(8, 15)

        for i in range(n_failures):
            ts = base_ts + timedelta(seconds=rng.randint(i * 5, i * 15))
            rows.append({
                "event_id":         _new_event_id(rng, used_ids),
                "timestamp":        _fmt(ts),
                "username":         target_user,
                "source_ip":        attacker_ip,
                "source_host":      "UNKNOWN-EXT",
                "destination_host": dc,
                "auth_type":        "NTLM",
                "logon_type":       "Network",
                "event_outcome":    "Failure",
                "scenario_label":   "brute_force",
                "is_suspicious":    1,
            })

        # Optional success after failures (~40 % chance — successful brute force)
        if rng.random() < 0.40:
            ts = base_ts + timedelta(seconds=n_failures * 12 + rng.randint(1, 30))
            rows.append({
                "event_id":         _new_event_id(rng, used_ids),
                "timestamp":        _fmt(ts),
                "username":         target_user,
                "source_ip":        attacker_ip,
                "source_host":      "UNKNOWN-EXT",
                "destination_host": dc,
                "auth_type":        "NTLM",
                "logon_type":       "Network",
                "event_outcome":    "Success",
                "scenario_label":   "brute_force",
                "is_suspicious":    1,
            })
    return rows


def _cred_stuffing_events(
    n_attacks: int, rng: random.Random, used_ids: set[str]
) -> list[dict]:
    """
    Credential stuffing: one external IP tries many different usernames,
    each attempted only once or twice (low per-user count, high diversity).
    Pattern: 10–20 distinct usernames from the same attacker IP in 10 min.
    """
    rows = []
    for _ in range(n_attacks):
        attacker_ip   = rng.choice(ATTACKER_IPS)
        dc            = rng.choice(DOMAIN_CONTROLLERS)
        base_ts       = _random_biz_ts(rng)
        targets       = rng.sample(USERNAMES, k=rng.randint(10, min(18, len(USERNAMES))))

        for i, user in enumerate(targets):
            ts = base_ts + timedelta(seconds=i * rng.randint(15, 45))
            outcome = "Success" if rng.random() < 0.08 else "Failure"
            rows.append({
                "event_id":         _new_event_id(rng, used_ids),
                "timestamp":        _fmt(ts),
                "username":         user,
                "source_ip":        attacker_ip,
                "source_host":      "UNKNOWN-EXT",
                "destination_host": dc,
                "auth_type":        "NTLM",
                "logon_type":       "Network",
                "event_outcome":    outcome,
                "scenario_label":   "cred_stuffing",
                "is_suspicious":    1,
            })
    return rows


def _off_hours_events(
    n_attacks: int, rng: random.Random, used_ids: set[str]
) -> list[dict]:
    """
    Off-hours access: a legitimate-looking internal account logs in at an
    unusual hour (outside 06:00–22:00 UTC), accessing sensitive servers.
    """
    rows = []
    for _ in range(n_attacks):
        idx  = rng.randrange(len(USERNAMES))
        user = USERNAMES[idx]
        ws   = WORKSTATIONS[idx]
        ip   = _make_internal_ip(rng)
        dest = rng.choice(SERVERS)       # targeting data/app servers, not just DC
        ts   = _random_offhours_ts(rng)
        rows.append({
            "event_id":         _new_event_id(rng, used_ids),
            "timestamp":        _fmt(ts),
            "username":         user,
            "source_ip":        ip,
            "source_host":      ws,
            "destination_host": dest,
            "auth_type":        rng.choices(AUTH_TYPES, AUTH_WEIGHTS)[0],
            "logon_type":       "RemoteInteractive",
            "event_outcome":    "Success",
            "scenario_label":   "off_hours_access",
            "is_suspicious":    1,
        })
    return rows


def _lateral_movement_events(
    n_attacks: int, rng: random.Random, used_ids: set[str]
) -> list[dict]:
    """
    Lateral movement: a compromised internal account authenticates to an
    unusual destination host that is NOT its normal workstation or server,
    then pivots to additional internal hosts within a short window.
    Pattern: user authenticates to 3–6 distinct servers in rapid succession
    (within 15 minutes) from a single source — abnormal host-fan-out.
    """
    rows = []
    for _ in range(n_attacks):
        idx          = rng.randrange(len(USERNAMES))
        user         = USERNAMES[idx]
        src_ip       = _make_internal_ip(rng)
        src_host     = WORKSTATIONS[rng.randrange(len(WORKSTATIONS))]  # may differ from user's own WS
        base_ts      = _random_biz_ts(rng)
        n_hops       = rng.randint(3, 6)
        # Pivot targets: all servers + other DCs (exclude user's own WS)
        targets = (SERVERS + DOMAIN_CONTROLLERS)
        hop_targets  = rng.sample(targets, k=min(n_hops, len(targets)))

        for i, dest in enumerate(hop_targets):
            ts = base_ts + timedelta(minutes=i * rng.randint(1, 4))
            rows.append({
                "event_id":         _new_event_id(rng, used_ids),
                "timestamp":        _fmt(ts),
                "username":         user,
                "source_ip":        src_ip,
                "source_host":      src_host,
                "destination_host": dest,
                "auth_type":        "NTLM",
                "logon_type":       "Network",
                "event_outcome":    "Success",
                "scenario_label":   "lateral_movement",
                "is_suspicious":    1,
            })
    return rows

# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_dataset(
    n_benign: int = N_BENIGN,
    n_brute_force: int = 15,
    n_cred_stuffing: int = 10,
    n_off_hours: int = 80,
    n_lateral: int = 12,
    seed: int = RANDOM_SEED,
    output_path: str | None = None,
) -> pd.DataFrame:
    """
    Generate and return a synthetic authentication event DataFrame.

    Parameters
    ----------
    n_benign        : number of normal background events
    n_brute_force   : number of brute-force attack campaigns
    n_cred_stuffing : number of credential-stuffing attack campaigns
    n_off_hours     : number of off-hours access events
    n_lateral       : number of lateral movement campaigns
    seed            : random seed for full reproducibility
    output_path     : if given, saves the CSV to this path (creates dirs)

    Returns
    -------
    pd.DataFrame with the SentinelFlow schema
    """
    rng      = random.Random(seed)
    used_ids: set[str] = set()

    all_rows: list[dict] = []
    all_rows.extend(_benign_events(n_benign,           rng, used_ids))
    all_rows.extend(_brute_force_events(n_brute_force, rng, used_ids))
    all_rows.extend(_cred_stuffing_events(n_cred_stuffing, rng, used_ids))
    all_rows.extend(_off_hours_events(n_off_hours,     rng, used_ids))
    all_rows.extend(_lateral_movement_events(n_lateral, rng, used_ids))

    df = pd.DataFrame(all_rows)

    # Sort by timestamp to simulate a real log stream
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df = df.sort_values("timestamp").reset_index(drop=True)
    # Serialise back to ISO-8601 string for CSV portability
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        df.to_csv(output_path, index=False)

    return df

# ---------------------------------------------------------------------------
# Validation helper (Phase 1 acceptance checks)
# ---------------------------------------------------------------------------

EXPECTED_COLUMNS: list[str] = [
    "event_id", "timestamp", "username", "source_ip", "source_host",
    "destination_host", "auth_type", "logon_type", "event_outcome",
    "scenario_label", "is_suspicious",
]

VALID_AUTH_TYPES    = {"Kerberos", "NTLM", "Negotiate"}
VALID_LOGON_TYPES   = {"Interactive", "Network", "RemoteInteractive"}
VALID_OUTCOMES      = {"Success", "Failure"}
VALID_LABELS        = {"benign", "brute_force", "cred_stuffing",
                       "off_hours_access", "lateral_movement"}

def validate_dataset(df: pd.DataFrame) -> None:
    """Run schema, uniqueness, timestamp, and distribution checks. Prints results."""
    print("=" * 65)
    print("  SentinelFlow - Dataset Validation Report")
    print("=" * 65)
    passed = 0
    failed = 0

    def ok(msg):
        nonlocal passed
        print(f"  [PASS] {msg}")
        passed += 1

    def fail(msg):
        nonlocal failed
        print(f"  [FAIL] {msg}")
        failed += 1

    # 1. Schema — all expected columns present
    missing_cols = [c for c in EXPECTED_COLUMNS if c not in df.columns]
    if not missing_cols:
        ok(f"Schema: all {len(EXPECTED_COLUMNS)} expected columns present")
    else:
        fail(f"Schema: missing columns - {missing_cols}")

    # 2. Row count
    ok(f"Row count: {len(df):,} total events generated")

    # 3. No missing values in any column
    null_counts = df[EXPECTED_COLUMNS].isnull().sum()
    total_nulls = null_counts.sum()
    if total_nulls == 0:
        ok("Missing values: 0 null values across all columns")
    else:
        fail(f"Missing values: {total_nulls} nulls found - {null_counts[null_counts > 0].to_dict()}")

    # 4. event_id uniqueness
    n_dup = df["event_id"].duplicated().sum()
    if n_dup == 0:
        ok(f"event_id uniqueness: all {len(df):,} IDs are unique")
    else:
        fail(f"event_id uniqueness: {n_dup} duplicate IDs found")

    # 5. event_id format (EVT-XXXXXXXX)
    bad_fmt = df["event_id"].str.match(r"^EVT-[A-F0-9]{8}$") == False
    if bad_fmt.sum() == 0:
        ok("event_id format: all IDs match EVT-XXXXXXXX pattern")
    else:
        fail(f"event_id format: {bad_fmt.sum()} IDs have incorrect format")

    # 6. Timestamp validity
    ts_series = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    bad_ts = ts_series.isnull().sum()
    if bad_ts == 0:
        ok("Timestamp validity: all timestamps parse correctly")
    else:
        fail(f"Timestamp validity: {bad_ts} unparseable timestamps")

    # 7. Timestamp range within simulation window
    ts_min = ts_series.min()
    ts_max = ts_series.max()
    sim_start_ts = pd.Timestamp(SIM_START)
    sim_end_ts   = pd.Timestamp(SIM_END)
    if ts_min >= sim_start_ts and ts_max <= sim_end_ts:
        ok(f"Timestamp range: {ts_min} -> {ts_max}  (within 7-day window)")
    else:
        fail(f"Timestamp range: min={ts_min}, max={ts_max}  (outside window)")

    # 8. Timestamps are sorted (ascending)
    is_sorted = ts_series.is_monotonic_increasing
    if is_sorted:
        ok("Timestamp ordering: dataset is sorted in ascending order")
    else:
        fail("Timestamp ordering: dataset is NOT sorted")

    # 9. Controlled-vocabulary fields
    bad_auth = (~df["auth_type"].isin(VALID_AUTH_TYPES)).sum()
    if bad_auth == 0:
        ok(f"auth_type vocabulary: all values in {VALID_AUTH_TYPES}")
    else:
        fail(f"auth_type vocabulary: {bad_auth} invalid values - {df['auth_type'][~df['auth_type'].isin(VALID_AUTH_TYPES)].unique()}")

    bad_logon = (~df["logon_type"].isin(VALID_LOGON_TYPES)).sum()
    if bad_logon == 0:
        ok(f"logon_type vocabulary: all values in {VALID_LOGON_TYPES}")
    else:
        fail(f"logon_type vocabulary: {bad_logon} invalid values")

    bad_outcome = (~df["event_outcome"].isin(VALID_OUTCOMES)).sum()
    if bad_outcome == 0:
        ok(f"event_outcome vocabulary: all values in {VALID_OUTCOMES}")
    else:
        fail(f"event_outcome vocabulary: {bad_outcome} invalid values")

    bad_labels = (~df["scenario_label"].isin(VALID_LABELS)).sum()
    if bad_labels == 0:
        ok(f"scenario_label vocabulary: all 5 expected labels present")
    else:
        fail(f"scenario_label vocabulary: {bad_labels} invalid labels - {df['scenario_label'][~df['scenario_label'].isin(VALID_LABELS)].unique()}")

    # 10. is_suspicious is binary
    bad_bin = (~df["is_suspicious"].isin([0, 1])).sum()
    if bad_bin == 0:
        ok("is_suspicious: binary (0/1) - no other values")
    else:
        fail(f"is_suspicious: {bad_bin} non-binary values found")

    # 11. Label/ground-truth consistency
    mismatch = (
        (df["scenario_label"] == "benign") & (df["is_suspicious"] == 1)
    ).sum() + (
        (df["scenario_label"] != "benign") & (df["is_suspicious"] == 0)
    ).sum()
    if mismatch == 0:
        ok("Label/ground-truth consistency: scenario_label <-> is_suspicious match")
    else:
        fail(f"Label/ground-truth consistency: {mismatch} mismatches")

    # 12. Class distribution
    print()
    print("  Label distribution:")
    label_counts = df["scenario_label"].value_counts()
    for label, count in label_counts.items():
        pct = count / len(df) * 100
        print(f"    {label:<22} {count:>5}  ({pct:5.1f} %)")

    suspicious_total = df["is_suspicious"].sum()
    benign_total     = (df["is_suspicious"] == 0).sum()
    print()
    print(f"    Benign (is_suspicious=0): {benign_total:>5}  ({benign_total/len(df)*100:.1f} %)")
    print(f"    Attack (is_suspicious=1): {suspicious_total:>5}  ({suspicious_total/len(df)*100:.1f} %)")

    # 13. Outcome distribution
    print()
    print("  Event outcome distribution:")
    for outcome, count in df["event_outcome"].value_counts().items():
        print(f"    {outcome:<12} {count:>5}  ({count/len(df)*100:.1f} %)")

    print()
    print("=" * 65)
    print(f"  Result: {passed} passed,  {failed} failed")
    print("=" * 65)
    if failed > 0:
        print("  WARNING: validation failures detected - review output above.")
    else:
        print("  All validation checks passed. Dataset is ready for Phase 2.")

# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SentinelFlow Synthetic Authentication Dataset Generator"
    )
    parser.add_argument("--seed",     type=int, default=RANDOM_SEED,  help="Random seed (default 42)")
    parser.add_argument("--benign",   type=int, default=N_BENIGN,     help="Number of benign events")
    parser.add_argument("--output",   type=str, default=OUTPUT_PATH,  help="Output CSV path")
    parser.add_argument("--validate", action="store_true",            help="Run validation after generation")
    args = parser.parse_args()

    print(f"[SentinelFlow] Generating synthetic dataset  (seed={args.seed}) ...")
    df = generate_dataset(seed=args.seed, n_benign=args.benign, output_path=args.output)
    print(f"[SentinelFlow] Saved {len(df):,} events -> {os.path.abspath(args.output)}")

    if args.validate:
        print()
        validate_dataset(df)
