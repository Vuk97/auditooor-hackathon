#!/usr/bin/env python3
"""Fail-closed accounting gate for V3 Kimi/MiniMax provider campaigns.

Provider fanout is acceleration, not proof. This gate checks that a campaign is
fully accounted for before provider output is allowed to influence hunter
briefs, proof queues, or learning ledgers.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CAMPAIGN_ID = "hackerman-v3-8kimi-8minimax"
SCHEMA = "auditooor.v3_provider_campaign_completeness_gate.v1"
BLOCKING_CLOSEOUT_STATUSES = {
    "blocked_no_mcp_receipt",
    "blocked_missing_model",
    "dispatched_no_output",
    "malformed_provider_output",
    "failed",
}
BLOCKING_VERIFICATION_STATUSES = {"pending", "needs_more_source", "blocked", "unknown"}


def _campaign_dir(workspace: Path, campaign_id: str) -> Path:
    return workspace / ".auditooor" / "provider_fanout" / campaign_id


def _latest(paths: Iterable[Path]) -> Path | None:
    existing = [path for path in paths if path.is_file()]
    return max(existing, key=lambda p: p.stat().st_mtime) if existing else None


def _run_dir_candidates(workspace: Path, campaign_id: str) -> list[Path]:
    runs_dir = _campaign_dir(workspace, campaign_id) / "runs"
    return sorted({path.parent for path in runs_dir.glob("*/v3_provider_fanout_run.json")})


def _artifact_mtime(path: Path) -> float:
    artifact_paths = [
        path / "v3_provider_fanout_run.json",
        path / "fanout_closeout.json",
        path / "v3_provider_local_verification_result.json",
    ]
    return max((artifact.stat().st_mtime for artifact in artifact_paths if artifact.is_file()), default=0.0)


def _latest_run_dir(workspace: Path, campaign_id: str) -> Path | None:
    candidates = _run_dir_candidates(workspace, campaign_id)
    if not candidates:
        return None
    return max(candidates, key=_artifact_mtime)


def _run_dir_summary(path: Path) -> dict[str, Any]:
    verification = _read_json(path / "v3_provider_local_verification_result.json")
    return {
        "run_dir": str(path),
        "artifact_mtime": _artifact_mtime(path),
        "run_json_present": (path / "v3_provider_fanout_run.json").is_file(),
        "closeout_present": (path / "fanout_closeout.json").is_file(),
        "local_verification_present": (path / "v3_provider_local_verification_result.json").is_file(),
        "local_verification_generated_at": verification.get("generated_at_utc") or verification.get("generated_at"),
    }


def _excluded_verification_results(workspace: Path, selected_run_dir: Path | None) -> list[str]:
    selected = (selected_run_dir / "v3_provider_local_verification_result.json").resolve() if selected_run_dir else None
    out: list[str] = []
    for path in workspace.glob(".auditooor/**/v3_provider_local_verification_result.json"):
        resolved = path.resolve()
        if selected is not None and resolved == selected:
            continue
        out.append(str(resolved))
    return sorted(out)


def _read_json(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _closure_queue_summary(path: Path | None) -> dict[str, Any]:
    data = _read_json(path)
    if not data:
        return {
            "present": False,
            "path": str(path or ""),
            "source_rows": 0,
            "deduped_items": 0,
            "terminal_judgment_rows": 0,
            "terminal_judgment_items": 0,
        }
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return {
        "present": True,
        "path": str(path or ""),
        "schema": data.get("schema"),
        "generated_at_utc": data.get("generated_at_utc"),
        "source_rows": int(summary.get("source_rows") or 0),
        "deduped_items": int(summary.get("deduped_items") or 0),
        "terminal_judgment_rows": int(summary.get("terminal_judgment_rows") or 0),
        "terminal_judgment_items": int(summary.get("terminal_judgment_items") or 0),
        "by_family": summary.get("by_family") if isinstance(summary.get("by_family"), dict) else {},
        "by_source_reviewer": (
            summary.get("by_source_reviewer")
            if isinstance(summary.get("by_source_reviewer"), dict)
            else {}
        ),
        "by_terminal_family": (
            summary.get("by_terminal_family")
            if isinstance(summary.get("by_terminal_family"), dict)
            else {}
        ),
    }


def _provider_counts(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for row in rows:
        counts[str(row.get("provider") or "unknown")] += 1
    return dict(sorted(counts.items()))


def _row_id(row: dict[str, Any]) -> str:
    return str(row.get("task_id") or row.get("queue_id") or row.get("id") or "")


def _has_receipt(row: dict[str, Any]) -> bool:
    receipt = row.get("mcp_receipt")
    if not isinstance(receipt, dict):
        return False
    return bool(receipt.get("path") and (receipt.get("sha256_16") or receipt.get("context_pack_id")))


def build_gate(
    workspace: Path,
    *,
    campaign_id: str = DEFAULT_CAMPAIGN_ID,
    queue_path: Path | None = None,
    run_path: Path | None = None,
    closeout_path: Path | None = None,
    verification_path: Path | None = None,
    closure_queue_path: Path | None = None,
    expected_kimi: int | None = None,
    expected_minimax: int | None = None,
) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    campaign_root = _campaign_dir(workspace, campaign_id)
    run_candidates = _run_dir_candidates(workspace, campaign_id)
    explicit_run = run_path is not None
    run_dir = Path(run_path).parent if run_path else _latest_run_dir(workspace, campaign_id)

    queue_path = queue_path or campaign_root / "v3_provider_fanout_queue.json"
    run_path = run_path or (run_dir / "v3_provider_fanout_run.json" if run_dir else None)
    closeout_path = closeout_path or (run_dir / "fanout_closeout.json" if run_dir else None)
    verification_path = verification_path or (run_dir / "v3_provider_local_verification_result.json" if run_dir else None)
    closure_queue_path = closure_queue_path or (workspace / ".auditooor" / "provider_closure_packet_queue.json")

    queue = _read_json(queue_path)
    run = _read_json(run_path)
    closeout = _read_json(closeout_path)
    verification = _read_json(verification_path)
    closure_queue = _closure_queue_summary(closure_queue_path)

    queue_rows = [row for row in queue.get("rows", []) if isinstance(row, dict)]
    run_rows = [row for row in run.get("rows", []) if isinstance(row, dict)]
    closeout_rows = [row for row in closeout.get("rows", []) if isinstance(row, dict)]
    verification_rows = [row for row in verification.get("rows", []) if isinstance(row, dict)]
    queue_counts = queue.get("provider_counts") if isinstance(queue.get("provider_counts"), dict) else _provider_counts(queue_rows)
    run_counts = _provider_counts(run_rows)
    closeout_counts = _provider_counts(closeout_rows)

    expected_counts = {
        "kimi": int(expected_kimi) if expected_kimi is not None else int(queue_counts.get("kimi") or 0),
        "minimax": int(expected_minimax) if expected_minimax is not None else int(queue_counts.get("minimax") or 0),
    }
    expected_total = sum(expected_counts.values()) or int(queue.get("total_tasks") or len(queue_rows))

    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    def block(code: str, detail: str, **extra: Any) -> None:
        blockers.append({"code": code, "detail": detail, **extra})

    for label, path, payload in (
        ("queue", queue_path, queue),
        ("run", run_path, run),
        ("closeout", closeout_path, closeout),
        ("local_verification", verification_path, verification),
    ):
        if not payload:
            block(f"missing_{label}", f"missing or unreadable {label} artifact", path=str(path or ""))

    if expected_total and len(run_rows) != expected_total:
        block("run_row_count_mismatch", f"run rows {len(run_rows)} != expected {expected_total}")
    if expected_total and len(closeout_rows) != expected_total:
        block("closeout_row_count_mismatch", f"closeout rows {len(closeout_rows)} != expected {expected_total}")
    for provider, expected in expected_counts.items():
        if expected and run_counts.get(provider, 0) != expected:
            block("provider_run_count_mismatch", f"{provider} run rows {run_counts.get(provider, 0)} != expected {expected}")
        if expected and closeout_counts.get(provider, 0) != expected:
            block("provider_closeout_count_mismatch", f"{provider} closeout rows {closeout_counts.get(provider, 0)} != expected {expected}")

    closeout_statuses = Counter(str(row.get("status") or "unknown") for row in closeout_rows)
    bad_statuses = sorted(set(closeout_statuses) & BLOCKING_CLOSEOUT_STATUSES)
    if bad_statuses:
        block("blocking_closeout_status", f"closeout has blocking statuses: {bad_statuses}", statuses=bad_statuses)

    for row in closeout_rows:
        task_id = _row_id(row)
        if not row.get("model"):
            block("missing_model", "closeout row missing model", task_id=task_id)
        if not _has_receipt(row):
            block("missing_mcp_receipt", "closeout row missing MCP receipt", task_id=task_id)
        output_path = Path(str(row.get("provider_output_path") or ""))
        if not output_path.is_file() or int(row.get("provider_output_bytes") or 0) <= 0:
            block("missing_provider_output", "provider output missing or empty", task_id=task_id, path=str(output_path))
        # Gap 1: zero-token burn means the run was mocked or did not actually execute
        if row.get("status") not in BLOCKING_CLOSEOUT_STATUSES and int(row.get("tokens_used") or 0) == 0:
            block("zero_token_burn", "closeout row has zero tokens_used; dispatch may not have run", task_id=task_id)

    required_verification = sum(1 for row in closeout_rows if row.get("local_verification_required"))
    if required_verification and len(verification_rows) < required_verification:
        block(
            "local_verification_row_count_mismatch",
            f"local verification rows {len(verification_rows)} < required {required_verification}",
        )
    verification_statuses = Counter(str(row.get("verification_status") or "unknown") for row in verification_rows)
    bad_verification = sorted(set(verification_statuses) & BLOCKING_VERIFICATION_STATUSES)
    if bad_verification:
        block("blocking_local_verification_status", f"local verification has unresolved statuses: {bad_verification}", statuses=bad_verification)
    summary = verification.get("summary") if isinstance(verification.get("summary"), dict) else {}
    for key in ("source_collection_required_rows", "terminal_judgment_required_rows"):
        value = int(summary.get(key) or 0)
        if value:
            block(key, f"local verification summary has {value} {key}")
    if verification_rows and not any(row.get("terminal_outcome") for row in verification_rows):
        warnings.append({"code": "no_terminal_learning_rows", "detail": "verification rows exist but none carry terminal_outcome"})

    # Gap 2 + Gap 3: scan verification rows for escaped promotion posture fields.
    # Every row produced by v3-provider-local-verify must carry advisory_only=True,
    # promotion_authority=False, submit_ready=False, and severity="none".
    # Any row that violates these invariants is an escape vector.
    provider_only_promotion_escapes: list[dict[str, Any]] = []
    for row in verification_rows:
        violations: list[str] = []
        if row.get("advisory_only") is False:
            violations.append("advisory_only=False")
        if row.get("promotion_authority") is True:
            violations.append("promotion_authority=True")
        if row.get("submit_ready") is True:
            violations.append("submit_ready=True")
        if str(row.get("severity") or "none").lower() not in {"none", "", "null"}:
            violations.append(f"severity={row.get('severity')!r}")
        if violations:
            provider_only_promotion_escapes.append({"queue_id": _row_id(row), "violations": violations})
    if provider_only_promotion_escapes:
        block(
            "provider_only_promotion_escape",
            f"{len(provider_only_promotion_escapes)} verification row(s) carry promotion-posture fields "
            "that must not be set on provider-sourced rows",
            escapes=provider_only_promotion_escapes,
        )
    if run_candidates and run_dir is not None and not explicit_run:
        lexical_latest = max(run_candidates, key=lambda path: path.name)
        if lexical_latest != run_dir:
            warnings.append(
                {
                    "code": "selected_older_named_run_by_mtime",
                    "detail": "A newer-looking run directory exists, but the selected run has the newest artifact mtime.",
                    "selected_run_dir": str(run_dir),
                    "newest_named_run_dir": str(lexical_latest),
                }
            )
    excluded_results = _excluded_verification_results(workspace, run_dir)
    if excluded_results:
        warnings.append(
            {
                "code": "broader_verification_results_excluded",
                "detail": "Campaign completeness is single-campaign/single-run; broad remediation queues must use v3-provider-source-collection-queue ALL_RESULTS=1.",
                "excluded_count": len(excluded_results),
            }
        )

    status = "pass" if not blockers else "fail"
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "campaign_id": campaign_id,
        "status": status,
        "verdict": status,
        "advisory_only": False,
        "promotion_authority": False,
        "submit_ready": False,
        # provider_only_promotion_escape_count MUST be 0 for any gate-passing campaign.
        # A non-zero value means at least one verification row carries promotion-posture
        # fields (promotion_authority, submit_ready, severity) that must never be set on
        # provider-sourced rows, making it an accounting escape that blocks the campaign.
        "provider_only_promotion_escape_count": len(provider_only_promotion_escapes),
        "artifacts": {
            "queue": str(queue_path),
            "run": str(run_path or ""),
            "closeout": str(closeout_path or ""),
            "local_verification": str(verification_path or ""),
            "closure_packet_queue": str(closure_queue_path or ""),
        },
        "selection": {
            "strategy": "explicit_run" if explicit_run else "latest_artifact_mtime",
            "selected_run_dir": str(run_dir or ""),
            "candidate_runs": [_run_dir_summary(path) for path in run_candidates],
            "excluded_verification_result_count": len(excluded_results),
        },
        "remediation_evidence": {
            "closure_packet_queue": closure_queue,
            "claim_guard": (
                "Closure packets route unresolved provider rows to source collection or "
                "terminal review; they do not resolve blockers until local verification "
                "rows are rerun with terminal outcomes."
            ),
        },
        "expected_counts": expected_counts,
        "observed_counts": {
            "queue": queue_counts,
            "run": run_counts,
            "closeout": closeout_counts,
            "local_verification_rows": len(verification_rows),
        },
        "status_counts": {
            "closeout": dict(sorted(closeout_statuses.items())),
            "local_verification": dict(sorted(verification_statuses.items())),
        },
        "blockers": blockers,
        "warnings": warnings,
        "policy": "Provider campaign output cannot affect hunter/proof/learning state until this gate passes.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=ROOT)
    parser.add_argument("--campaign-id", default=DEFAULT_CAMPAIGN_ID)
    parser.add_argument("--queue", type=Path)
    parser.add_argument("--run", type=Path)
    parser.add_argument("--closeout", type=Path)
    parser.add_argument("--local-verification", type=Path)
    parser.add_argument("--closure-queue", type=Path)
    parser.add_argument("--expected-kimi", type=int)
    parser.add_argument("--expected-minimax", type=int)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)
    payload = build_gate(
        args.workspace,
        campaign_id=args.campaign_id,
        queue_path=args.queue,
        run_path=args.run,
        closeout_path=args.closeout,
        verification_path=args.local_verification,
        closure_queue_path=args.closure_queue,
        expected_kimi=args.expected_kimi,
        expected_minimax=args.expected_minimax,
    )
    if args.out_json:
        out = args.out_json.expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json or not args.out_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if args.strict and payload["status"] != "pass" else 0


if __name__ == "__main__":
    raise SystemExit(main())
