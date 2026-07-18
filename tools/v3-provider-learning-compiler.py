#!/usr/bin/env python3
"""Compile V3 provider local-verification results into terminal learning rows.

Only verifier-terminal rows are compiled. Provider closeout/queue rows remain
lineage, never promoted evidence.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CAMPAIGN_ID = "hackerman-v3-8kimi-8minimax"
DEFAULT_LEDGER = ROOT / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
EXPECTED_RESULT_SCHEMA = "auditooor.v3_provider_local_verification_result.v1"
TERMINAL_OUTCOMES = {
    "verified_actionable",
    "verified_no_action",
    "rejected_oos",
    "rejected_duplicate",
    "rejected_false_positive",
    "needs_more_source",
    "blocked_missing_receipt",
    "blocked_missing_model",
    "blocked_no_output",
    "blocked_malformed_output",
}


def _default_campaign_dir(workspace: Path, campaign_id: str) -> Path:
    return workspace / ".auditooor" / "provider_fanout" / campaign_id


def _latest_result(workspace: Path, campaign_id: str) -> Path:
    runs_dir = _default_campaign_dir(workspace, campaign_id) / "runs"
    candidates = sorted(runs_dir.glob("*/v3_provider_local_verification_result.json"))
    if not candidates:
        raise SystemExit(f"[v3-provider-learning-compiler] no local verification results under {runs_dir}")
    return candidates[-1]


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object JSON in {path}")
    return payload


def _utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _terminal_kind(outcome: str, claim_kind: str) -> str:
    if outcome == "verified_actionable":
        if claim_kind in {"proof_obligation", "workflow_gap"}:
            return "hacker_question"
        return "typed_lesson"
    if outcome in {"rejected_oos", "rejected_duplicate", "rejected_false_positive"}:
        return "kill_reason"
    if outcome == "verified_no_action":
        return "NO_ACTION"
    if outcome == "needs_more_source" or outcome.startswith("blocked_"):
        return "NO_ACTION"
    return "NO_ACTION"


def _primary_for(outcome: str, route: str) -> str:
    if outcome == "rejected_oos":
        return "OOS"
    if outcome == "rejected_duplicate":
        return "dupe"
    if outcome == "rejected_false_positive":
        return "source_reachability"
    if outcome == "needs_more_source":
        return "source_reachability"
    if outcome.startswith("blocked_"):
        return "harness_gap"
    if route == "fixture_needed":
        return "harness_gap"
    return "methodology"


def _evidence_polarity(outcome: str) -> str:
    if outcome == "verified_actionable":
        return "supports"
    if outcome in {"rejected_oos", "rejected_duplicate", "rejected_false_positive"}:
        return "contradicts"
    if outcome in {"needs_more_source", "verified_no_action"} or outcome.startswith("blocked_"):
        return "limits"
    return "context_only"


def _reuse_action(outcome: str, claim_kind: str) -> str:
    if outcome == "verified_actionable":
        return "surface_as_hacker_question_after_human_review" if claim_kind == "proof_obligation" else "surface_as_typed_lesson"
    if outcome == "needs_more_source":
        return "do_not_use_until_primary_source_or_local_proof"
    if outcome.startswith("blocked_"):
        return "do_not_use_provider_row_rerun_required"
    if outcome in {"rejected_oos", "rejected_duplicate", "rejected_false_positive", "verified_no_action"}:
        return "use_as_kill_or_stop_condition_only"
    return "manual_review_only"


def _row_key(record: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(record.get("source") or ""),
        str(record.get("run_id") or ""),
        str(record.get("queue_id") or ""),
        str(record.get("terminal_outcome") or ""),
    )


def _existing_keys(ledger: Path) -> set[tuple[str, str, str, str]]:
    keys: set[tuple[str, str, str, str]] = set()
    if not ledger.is_file():
        return keys
    for raw in ledger.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            keys.add(_row_key(row))
    return keys


def _safe_terminal_row(row: dict[str, Any], payload: dict[str, Any]) -> bool:
    outcome = str(row.get("terminal_outcome") or "")
    if payload.get("schema") != EXPECTED_RESULT_SCHEMA or outcome not in TERMINAL_OUTCOMES:
        return False
    allowed = {str(item) for item in row.get("terminal_outcome_options") or []}
    return (
        outcome in allowed
        and row.get("terminal_safe") is True
        and row.get("learning_ledger_ready") is True
        and row.get("local_verification_required") is False
        and row.get("advisory_only") is True
        and row.get("promotion_authority") is False
        and row.get("submit_ready") is False
        and str(row.get("severity") or "") == "none"
    )


def _compile_record(row: dict[str, Any], payload: dict[str, Any], result_path: Path, generated_at: str) -> dict[str, Any] | None:
    outcome = str(row.get("terminal_outcome") or "")
    if not outcome:
        return None
    claim = row.get("claim") if isinstance(row.get("claim"), dict) else {}
    claim_kind = str(claim.get("kind") or "lesson_candidate")
    record = {
        "schema": "auditooor.agent_learning_ledger.v1",
        "ts": generated_at,
        "source": "v3-provider-local-verification",
        "campaign_id": payload.get("campaign_id"),
        "run_id": payload.get("run_id"),
        "queue_id": row.get("queue_id"),
        "task_id": row.get("task_id"),
        "provider": row.get("provider"),
        "model": row.get("model"),
        "terminal_kind": _terminal_kind(outcome, claim_kind),
        "terminal_outcome": outcome,
        "proposition": claim.get("summary") or row.get("task_id") or row.get("queue_id"),
        "evidence_polarity": _evidence_polarity(outcome),
        "primary_for": _primary_for(outcome, str(row.get("route") or "")),
        "reuse_action": _reuse_action(outcome, claim_kind),
        "evidence_tier": "secondary",
        "quarantine": True,
        "local_verification_required": False,
        "source_verification_result": str(result_path),
        "source_provider_row": row.get("source_provider_row"),
        "provider_lineage": {
            "provider_output_path": (row.get("source_provider_row") or {}).get("provider_output_path")
            if isinstance(row.get("source_provider_row"), dict)
            else None,
            "provider_claim_id": claim.get("provider_claim_id"),
            "provider_verdict": claim.get("provider_verdict"),
            "provider_output_advisory_only": True,
        },
        "verification": row.get("verification"),
        "promotion_authority": False,
        "submit_ready": False,
        "severity": "none",
        "selected_impact": "",
    }
    return record


def compile_learning(result_path: Path, ledger: Path) -> dict[str, Any]:
    payload = _read_json(result_path)
    generated_at = _utc_now_iso()
    terminal_rows = [
        row
        for row in payload.get("rows", [])
        if isinstance(row, dict) and row.get("terminal_outcome")
    ]
    unsafe_rows = [row for row in terminal_rows if not _safe_terminal_row(row, payload)]
    rows = [
        record
        for row in terminal_rows
        if _safe_terminal_row(row, payload)
        for record in [_compile_record(row, payload, result_path, generated_at)]
        if record is not None
    ]
    existing = _existing_keys(ledger)
    appended: list[dict[str, Any]] = []
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with ledger.open("a", encoding="utf-8") as fh:
        for record in rows:
            key = _row_key(record)
            if key in existing:
                continue
            existing.add(key)
            appended.append(record)
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    return {
        "schema": "auditooor.v3_provider_learning_compile.v1",
        "generated_at_utc": generated_at,
        "source_result": str(result_path),
        "learning_ledger_path": str(ledger),
        "terminal_rows_seen": len(terminal_rows),
        "unsafe_terminal_rows_skipped": len(unsafe_rows),
        "rows_appended": len(appended),
        "rows_skipped_existing": len(rows) - len(appended),
        "by_terminal_outcome": payload.get("summary", {}).get("by_terminal_outcome", {}),
        "advisory_only": True,
        "promotion_authority": False,
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=ROOT)
    parser.add_argument("--campaign-id", default=DEFAULT_CAMPAIGN_ID)
    parser.add_argument("--result", type=Path, default=None)
    parser.add_argument("--ledger", type=Path, default=None)
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    result_path = args.result.expanduser().resolve() if args.result else _latest_result(workspace, args.campaign_id)
    ledger = args.ledger.expanduser().resolve() if args.ledger else workspace / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
    payload = compile_learning(result_path, ledger)
    if args.out_json:
        out_json = args.out_json.expanduser().resolve()
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
