#!/usr/bin/env python3
"""Emit one Phase E A/B outcome packet (two JSONL rows) for an engagement."""
from __future__ import annotations

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
ROW_SCHEMA = "auditooor.phase_e_ab_outcome_row.v1"
MIN_OUTCOME_OBSERVED_AT_UTC = datetime(2026, 5, 24, tzinfo=timezone.utc)


def _parse_utc_datetime(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_metric(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0 or parsed > 100:
        raise argparse.ArgumentTypeError("metric values must be in [0, 100]")
    return parsed


def _require_evidence(path_str: str) -> str:
    candidate = Path(path_str).expanduser()
    if candidate.is_absolute():
        if candidate.exists():
            return str(candidate)
        raise argparse.ArgumentTypeError(f"evidence path does not exist: {path_str}")

    repo_candidate = REPO / candidate
    if repo_candidate.exists():
        return path_str
    if candidate.exists():
        return str(candidate.resolve())
    else:
        raise argparse.ArgumentTypeError(f"evidence path does not exist: {path_str}")


def _build_row(
    *,
    measurement_window_id: str,
    engagement_id: str,
    pair_id: str,
    cohort: str,
    outcome_observed_at_utc: str,
    ppe: float,
    frph: float,
    prqs: float,
    supporting: float,
    evidence_path: str,
    notes: str | None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "schema": ROW_SCHEMA,
        "measurement_window_id": measurement_window_id,
        "engagement_id": engagement_id,
        "pair_id": pair_id,
        "cohort": cohort,
        "outcome_observed_at_utc": outcome_observed_at_utc,
        "metrics": {
            "ppe": ppe,
            "frph": frph,
            "prqs": prqs,
            "supporting": supporting,
        },
        "evidence_paths": [evidence_path],
    }
    if notes:
        row["notes"] = notes
    return row


def build_packet(args: argparse.Namespace) -> list[dict[str, Any]]:
    observed = _parse_utc_datetime(args.outcome_observed_at_utc)
    if observed < MIN_OUTCOME_OBSERVED_AT_UTC:
        raise ValueError("outcome_observed_at_utc must be >= 2026-05-24T00:00:00Z")

    row_a = _build_row(
        measurement_window_id=args.measurement_window_id,
        engagement_id=args.engagement_id,
        pair_id=args.pair_id,
        cohort="A",
        outcome_observed_at_utc=args.outcome_observed_at_utc,
        ppe=args.a_ppe,
        frph=args.a_frph,
        prqs=args.a_prqs,
        supporting=args.a_supporting,
        evidence_path=args.a_evidence_path,
        notes=args.a_notes,
    )
    row_b = _build_row(
        measurement_window_id=args.measurement_window_id,
        engagement_id=args.engagement_id,
        pair_id=args.pair_id,
        cohort="B",
        outcome_observed_at_utc=args.outcome_observed_at_utc,
        ppe=args.b_ppe,
        frph=args.b_frph,
        prqs=args.b_prqs,
        supporting=args.b_supporting,
        evidence_path=args.b_evidence_path,
        notes=args.b_notes,
    )
    return [row_a, row_b]


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Emit one valid Phase E A/B JSONL packet for a real engagement.")
    p.add_argument("--measurement-window-id", required=True)
    p.add_argument("--engagement-id", required=True)
    p.add_argument("--pair-id", required=True)
    p.add_argument("--outcome-observed-at-utc", required=True)
    p.add_argument("--a-evidence-path", required=True, type=_require_evidence)
    p.add_argument("--b-evidence-path", required=True, type=_require_evidence)
    p.add_argument("--a-ppe", required=True, type=_parse_metric)
    p.add_argument("--a-frph", required=True, type=_parse_metric)
    p.add_argument("--a-prqs", required=True, type=_parse_metric)
    p.add_argument("--a-supporting", required=True, type=_parse_metric)
    p.add_argument("--b-ppe", required=True, type=_parse_metric)
    p.add_argument("--b-frph", required=True, type=_parse_metric)
    p.add_argument("--b-prqs", required=True, type=_parse_metric)
    p.add_argument("--b-supporting", required=True, type=_parse_metric)
    p.add_argument("--a-notes")
    p.add_argument("--b-notes")
    p.add_argument("--out", required=True, help="JSONL destination path.")
    p.add_argument("--append", action="store_true", help="Append instead of overwrite.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    rows = build_packet(args)
    out_path = Path(args.out).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.append else "w"
    with out_path.open(mode, encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, allow_nan=False, sort_keys=True) + "\n")
    print(json.dumps({"rows_written": 2, "out": str(out_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
