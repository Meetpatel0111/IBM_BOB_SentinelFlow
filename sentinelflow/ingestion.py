"""
SentinelFlow - ingestion.py
===========================
Loads, validates, and normalises an authentication-event CSV into a
pandas DataFrame ready for the detection engine.

All timestamps are returned as timezone-aware UTC pandas Timestamps.
Ground-truth columns (scenario_label, is_suspicious) are preserved in the
output but must NOT be used by any detection logic.

Usage
-----
    from sentinelflow.ingestion import load_events
    df = load_events("data/synthetic_auth_logs.csv")
"""

from __future__ import annotations

import os
from typing import Optional

import pandas as pd

# ---------------------------------------------------------------------------
# Schema definition
# ---------------------------------------------------------------------------

REQUIRED_COLUMNS: list[str] = [
    "event_id",
    "timestamp",
    "username",
    "source_ip",
    "source_host",
    "destination_host",
    "auth_type",
    "logon_type",
    "event_outcome",
]

# Ground-truth columns: present in the synthetic dataset but forbidden as
# detection features.  They are carried through for downstream evaluation.
GROUND_TRUTH_COLUMNS: list[str] = ["scenario_label", "is_suspicious"]

VALID_AUTH_TYPES: frozenset[str] = frozenset({"Kerberos", "NTLM", "Negotiate"})
VALID_LOGON_TYPES: frozenset[str] = frozenset(
    {"Interactive", "Network", "RemoteInteractive"}
)
VALID_OUTCOMES: frozenset[str] = frozenset({"Success", "Failure"})
EVENT_ID_PATTERN: str = r"^EVT-[A-F0-9]{8}$"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_events(
    path: str,
    strict_vocab: bool = True,
    require_ground_truth: bool = False,
) -> pd.DataFrame:
    """Load and validate an authentication-event CSV.

    Parameters
    ----------
    path:
        Filesystem path to the CSV file.
    strict_vocab:
        When True (default), reject rows containing values outside the
        defined controlled vocabularies for auth_type, logon_type, and
        event_outcome.  Set False only for exploratory analysis.
    require_ground_truth:
        When True, raise IngestionError if scenario_label / is_suspicious
        are absent.  Default False so the engine works on unlabelled data.

    Returns
    -------
    pd.DataFrame with normalised columns and UTC timestamps.

    Raises
    ------
    IngestionError
        Descriptive error for any schema or data-quality problem found.
    FileNotFoundError
        When the CSV file does not exist.
    """
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Dataset not found: {path}")

    try:
        raw = pd.read_csv(path, dtype=str)
    except Exception as exc:  # noqa: BLE001
        raise IngestionError(f"Failed to parse CSV '{path}': {exc}") from exc

    if raw.empty:
        raise IngestionError(f"Dataset is empty: {path}")

    # 1. Required columns
    missing = [c for c in REQUIRED_COLUMNS if c not in raw.columns]
    if missing:
        raise IngestionError(
            f"Missing required columns: {missing}\n"
            f"Found: {list(raw.columns)}"
        )

    # 2. Ground-truth columns (optional by default)
    if require_ground_truth:
        missing_gt = [c for c in GROUND_TRUTH_COLUMNS if c not in raw.columns]
        if missing_gt:
            raise IngestionError(
                f"Ground-truth columns required but missing: {missing_gt}"
            )

    df = raw.copy()

    # 3. Null check on required columns
    null_counts = df[REQUIRED_COLUMNS].isnull().sum()
    cols_with_nulls = null_counts[null_counts > 0]
    if not cols_with_nulls.empty:
        raise IngestionError(
            f"Null values found in required columns:\n{cols_with_nulls.to_dict()}"
        )

    # 4. Strip whitespace from string columns
    for col in REQUIRED_COLUMNS:
        df[col] = df[col].str.strip()

    # 5. event_id uniqueness
    dup_mask = df["event_id"].duplicated(keep=False)
    if dup_mask.any():
        n_dup = dup_mask.sum()
        examples = df.loc[dup_mask, "event_id"].unique()[:5].tolist()
        raise IngestionError(
            f"{n_dup} duplicate event_id values found. Examples: {examples}"
        )

    # 6. event_id format
    bad_fmt = ~df["event_id"].str.match(EVENT_ID_PATTERN, na=False)
    if bad_fmt.any():
        n_bad = bad_fmt.sum()
        examples = df.loc[bad_fmt, "event_id"].head(3).tolist()
        raise IngestionError(
            f"{n_bad} event_id values do not match EVT-XXXXXXXX. Examples: {examples}"
        )

    # 7. Timestamp parsing (UTC)
    parsed_ts = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    bad_ts = parsed_ts.isnull()
    if bad_ts.any():
        n_bad = bad_ts.sum()
        examples = df.loc[bad_ts, "timestamp"].head(3).tolist()
        raise IngestionError(
            f"{n_bad} timestamps could not be parsed. Examples: {examples}"
        )
    df["timestamp"] = parsed_ts

    # 8. Controlled vocabulary checks (optional but default)
    if strict_vocab:
        _check_vocab(df, "auth_type", VALID_AUTH_TYPES)
        _check_vocab(df, "logon_type", VALID_LOGON_TYPES)
        _check_vocab(df, "event_outcome", VALID_OUTCOMES)

    # 9. Ground-truth column normalisation (when present)
    if "is_suspicious" in df.columns:
        df["is_suspicious"] = pd.to_numeric(df["is_suspicious"], errors="coerce")
        bad_bin = ~df["is_suspicious"].isin([0, 1])
        if bad_bin.any():
            raise IngestionError(
                f"{bad_bin.sum()} is_suspicious values are not 0 or 1."
            )
        df["is_suspicious"] = df["is_suspicious"].astype(int)

    # 10. Sort by timestamp (ascending) for deterministic processing order
    df = df.sort_values("timestamp").reset_index(drop=True)

    return df


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_vocab(df: pd.DataFrame, column: str, valid: frozenset[str]) -> None:
    """Raise IngestionError if ``column`` contains values outside ``valid``."""
    bad_mask = ~df[column].isin(valid)
    if bad_mask.any():
        bad_vals = df.loc[bad_mask, column].unique().tolist()
        raise IngestionError(
            f"Column '{column}' contains invalid values: {bad_vals}. "
            f"Expected one of: {sorted(valid)}"
        )


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class IngestionError(ValueError):
    """Raised when the input dataset fails schema or data-quality checks."""
