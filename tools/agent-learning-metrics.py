#!/usr/bin/env python3
"""agent-learning-metrics.py - Lane K K8 metrics emitter.

Computes the K8 metric set over a workspace's terminal agent-learning ledger
(``.auditooor/agent_artifacts/learning_ledger.jsonl``, compiled by
``tools/agent-learning-compiler.py``) and the matching miner report
(``agent_artifact_mining_report.json``).

K8 acceptance: this lane is successful when artifact learning saves proof time
or prevents a bad filing, not when it merely counts more files.  The metrics
below make that visible:

* ``artifact_accounting_coverage``           - mined artifacts that compiled to a terminal row.
* ``unclassified_high_critical_artifacts``   - High/Critical artifacts with no terminal row.
* ``provider_only_promotion_escape_count``   - provider-only rows that reached proof_artifact (target 0).
* ``learning_promotion_rate``                - terminal rows that became a reusable improvement (K4 reuse_action != none).
* ``kill_reason_reuse_rate``                 - kill_reason rows that carry an add_kill_rubric reuse_action.
* ``triager_objection_pre_submit_caught_count`` - triager_objection rows wired to add_pre_submit_gate.
* ``proof_artifact_binding_rate``            - proof_artifact rows backed by a primary signal.
* ``closeout_block_count``                   - terminal rows that would block a strict closeout.
* ``time_to_learning``                       - mtime gap (hours) between newest miner input and ledger.

The tool is offline-only and deterministic.  It does not promote anything.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any, Sequence


SCHEMA = "auditooor.agent_learning_metrics.v1"
DEFAULT_REPORT = "agent_artifact_mining_report.json"
DEFAULT_LEDGER = ".auditooor/agent_artifacts/learning_ledger.jsonl"

HIGH_CRITICAL_TOKENS = {"high", "critical", "crit"}
REUSE_IMPROVEMENT_ACTIONS = {
    "add_detector",
    "add_kill_rubric",
    "add_pre_submit_gate",
    "add_originality_check",
    "add_provider_prompt_constraint",
    "add_harness_template",
    "add_hacker_question",
}


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return payload if isinstance(payload, dict) else None


def _read_ledger(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _kind(row: dict[str, Any]) -> str:
    return str(row.get("terminal_kind") or row.get("kind") or "").strip()


def _severity(record: dict[str, Any]) -> str:
    return str(record.get("severity") or record.get("severity_guess") or "").strip().lower()


def _ratio(num: int, denom: int) -> float:
    return round(num / denom, 4) if denom else 0.0


def compute_metrics(workspace: Path, report: Path, ledger: Path) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    report = report.expanduser().resolve()
    ledger = ledger.expanduser().resolve()

    report_payload = _read_json(report)
    rows = _read_ledger(ledger)

    artifacts: list[dict[str, Any]] = []
    if report_payload:
        raw = report_payload.get("artifacts")
        if isinstance(raw, list):
            artifacts = [a for a in raw if isinstance(a, dict)]

    artifact_ids = {
        str(a.get("artifact_id") or a.get("id") or "").strip()
        for a in artifacts
        if str(a.get("artifact_id") or a.get("id") or "").strip()
    }
    ledger_artifact_ids = {
        str(r.get("artifact_id") or "").strip()
        for r in rows
        if str(r.get("artifact_id") or "").strip()
    }

    covered = artifact_ids & ledger_artifact_ids
    unclassified = sorted(artifact_ids - ledger_artifact_ids)
    unclassified_high_critical = sorted(
        str(a.get("artifact_id") or a.get("id") or "").strip()
        for a in artifacts
        if str(a.get("artifact_id") or a.get("id") or "").strip() in set(unclassified)
        and _severity(a) in HIGH_CRITICAL_TOKENS
    )

    terminal_rows = [r for r in rows if _kind(r)]
    promoted = [r for r in terminal_rows if str(r.get("reuse_action") or "").strip() in REUSE_IMPROVEMENT_ACTIONS]
    kill_rows = [r for r in terminal_rows if _kind(r) == "kill_reason"]
    kill_reused = [r for r in kill_rows if str(r.get("reuse_action") or "").strip() == "add_kill_rubric"]
    objection_rows = [r for r in terminal_rows if _kind(r) == "triager_objection"]
    objection_pre_submit = [
        r for r in objection_rows if str(r.get("reuse_action") or "").strip() == "add_pre_submit_gate"
    ]
    proof_rows = [r for r in terminal_rows if _kind(r) == "proof_artifact"]
    proof_bound = [
        r
        for r in proof_rows
        if r.get("is_primary_signal") is True or r.get("can_promote_to_proof") is True
    ]
    provider_only_escapes = [
        r for r in terminal_rows if r.get("provider_only") is True and _kind(r) == "proof_artifact"
    ]
    # A row that would block a strict closeout: NO_ACTION without a reason, or a
    # terminal row missing K3a/K4 scope.
    closeout_blocks = 0
    for r in terminal_rows:
        if _kind(r) == "NO_ACTION" and not str(r.get("reason") or "").strip():
            closeout_blocks += 1
            continue
        if not str(r.get("proposition") or "").strip():
            closeout_blocks += 1
            continue
        if not str(r.get("reuse_action") or "").strip():
            closeout_blocks += 1

    # time_to_learning: hours between the newest miner input and the ledger
    # write.  Lower is better; learning that lags far behind discovery is stale.
    time_to_learning_hours: float | None = None
    if ledger.is_file():
        ledger_mtime = ledger.stat().st_mtime
        newest_input = 0.0
        if report.is_file():
            newest_input = max(newest_input, report.stat().st_mtime)
        if report_payload:
            for key in ("latest_input_mtime_epoch", "newest_input_mtime"):
                val = report_payload.get(key)
                if isinstance(val, (int, float)):
                    newest_input = max(newest_input, float(val))
        if newest_input > 0:
            time_to_learning_hours = round((ledger_mtime - newest_input) / 3600.0, 3)

    metrics = {
        "artifact_accounting_coverage": _ratio(len(covered), len(artifact_ids)),
        "artifact_accounting_covered": len(covered),
        "artifact_accounting_total": len(artifact_ids),
        "unclassified_artifact_count": len(unclassified),
        "unclassified_high_critical_artifacts": len(unclassified_high_critical),
        "unclassified_high_critical_ids": unclassified_high_critical[:20],
        "provider_only_promotion_escape_count": len(provider_only_escapes),
        "learning_promotion_rate": _ratio(len(promoted), len(terminal_rows)),
        "learning_promotion_count": len(promoted),
        "kill_reason_reuse_rate": _ratio(len(kill_reused), len(kill_rows)),
        "triager_objection_pre_submit_caught_count": len(objection_pre_submit),
        "proof_artifact_binding_rate": _ratio(len(proof_bound), len(proof_rows)),
        "proof_artifact_count": len(proof_rows),
        "closeout_block_count": closeout_blocks,
        "time_to_learning_hours": time_to_learning_hours,
        "terminal_row_count": len(terminal_rows),
    }

    # Lane K K8 acceptance gate - the lane is "healthy" only when artifacts are
    # fully accounted for, no provider-only row escaped to proof, and no
    # high/critical artifact is unclassified.
    healthy = (
        metrics["provider_only_promotion_escape_count"] == 0
        and metrics["unclassified_high_critical_artifacts"] == 0
        and metrics["closeout_block_count"] == 0
        and (metrics["artifact_accounting_total"] == 0 or metrics["artifact_accounting_coverage"] >= 0.99)
    )

    return {
        "schema": SCHEMA,
        "generated_at_utc": _utc_now(),
        "workspace": str(workspace),
        "source_report": str(report),
        "learning_ledger_path": str(ledger),
        "report_present": report_payload is not None,
        "ledger_present": ledger.is_file(),
        "metrics": metrics,
        "k8_healthy": healthy,
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when the K8 health gate fails.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    report = args.report.expanduser().resolve() if args.report else workspace / DEFAULT_REPORT
    ledger = args.ledger.expanduser().resolve() if args.ledger else workspace / DEFAULT_LEDGER
    payload = compute_metrics(workspace, report, ledger)
    if args.out_json:
        out = args.out_json.expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif not args.out_json:
        m = payload["metrics"]
        print(
            f"agent-learning-metrics: k8_healthy={payload['k8_healthy']} "
            f"coverage={m['artifact_accounting_coverage']} "
            f"promotion_rate={m['learning_promotion_rate']} "
            f"provider_escapes={m['provider_only_promotion_escape_count']} "
            f"unclassified_hc={m['unclassified_high_critical_artifacts']} "
            f"closeout_blocks={m['closeout_block_count']}"
        )
    if args.strict and not payload["k8_healthy"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
