#!/usr/bin/env python3
"""Convert callgraph limitation execution rows into terminal closure evidence.

This is an advisory close-out ledger for the PR560 callgraph limitation lane.
It consumes a worker execution artifact, attaches local fixture-smoke/source
evidence where available, and enriches terminal blockers with exact missing
evidence. It does not rewrite detectors, prove impact, or make any row
promotion-ready.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "auditooor.callgraph_terminal_conversion.v1"
FIXTURE_EVIDENCE_SCHEMA_VERSION = "auditooor.callgraph_fixture_smoke_evidence.v1"
GENERATED_EVIDENCE_CLASS = "generated_hypothesis"
SCAFFOLDED_EVIDENCE_CLASS = "scaffolded_unverified"
SOURCE_SHAPE_LIMITATIONS = [
    "conversion rows are advisory close-out evidence only",
    "detector fixture smoke does not prove callgraph completeness",
    "semantic graph rows are source-shape evidence, not compiler-backed fixpoints",
    "lint blockers remain open until detector prose is narrowed or callgraph predicates land",
    "no severity, selected impact, PoC posture, or submission readiness may be inferred",
]


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SystemExit(f"[callgraph-terminal-conversion] cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[callgraph-terminal-conversion] invalid JSON {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"[callgraph-terminal-conversion] expected object JSON: {path}")
    return data


def _safe_rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path)


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _hits_from_log(path: Path) -> int | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    matches = re.findall(r"total hits:\s*(\d+)", text)
    return int(matches[-1]) if matches else None


def _command_from_log(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    match = re.search(r"\[hint\] save full output:\s*(.+)", text)
    return match.group(1).strip() if match else ""


def _slug_from_detector(detector_argument: str) -> str:
    return detector_argument.replace("-", "_")


def _smoke_logs_for(row: dict[str, Any], smoke_log_dir: Path) -> dict[str, Any]:
    detector = str(row.get("detector_argument") or "")
    slug = _slug_from_detector(detector)
    vulnerable = smoke_log_dir / f"{slug}_vulnerable_{detector}.log"
    clean = smoke_log_dir / f"{slug}_clean_{detector}.log"
    vuln_hits = _hits_from_log(vulnerable)
    clean_hits = _hits_from_log(clean)
    passed = vuln_hits is not None and clean_hits is not None and vuln_hits >= 1 and clean_hits == 0
    return {
        "passed": passed,
        "vulnerable_hits": vuln_hits,
        "clean_hits": clean_hits,
        "vulnerable_log": _safe_rel(vulnerable) if vulnerable.exists() else "",
        "clean_log": _safe_rel(clean) if clean.exists() else "",
        "vulnerable_log_sha256": _sha256(vulnerable) if vulnerable.exists() else "",
        "clean_log_sha256": _sha256(clean) if clean.exists() else "",
        "vulnerable_command_hint": _command_from_log(vulnerable),
        "clean_command_hint": _command_from_log(clean),
    }


def _blocking_axis(row: dict[str, Any]) -> str:
    lane = str(row.get("action_lane") or "")
    if lane == "callgraph_required":
        return "missing_detector_callgraph_predicate"
    if lane == "semantic_graph_required":
        return "missing_semantic_source_shape_row"
    if lane == "fixture_pair_required":
        return "missing_fixture_pair_or_smoke"
    if lane == "claim_scope_required":
        return "prose_claim_still_callgraph_sensitive"
    if lane == "terminal_decision_required":
        return "terminal_decision_advisory_only"
    return "unknown_callgraph_terminal_axis"


def _required_evidence(row: dict[str, Any]) -> list[str]:
    lane = str(row.get("action_lane") or "")
    if lane == "callgraph_required":
        return [
            "detector diff using an accepted Slither/predicate callgraph read",
            "detector-lint --fail-inter-contract-claim-without-callgraph clean for this detector",
            "paired vulnerable/clean fixture smoke after the predicate change",
        ]
    if lane == "semantic_graph_required":
        return [
            "semantic_graph relation_edges or multi_hop_paths row matching the detector slug/claim",
            "source file, line, source component, target component, and method evidence",
        ]
    if lane == "fixture_pair_required":
        return [
            "vulnerable fixture with positive detector hit",
            "clean fixture with zero detector hits",
            "captured detector smoke command output",
        ]
    if lane == "claim_scope_required":
        return [
            "module docstring/HELP/WIKI claim narrowed to local syntax",
            "or detector-side callgraph evidence that supports the original claim",
        ]
    return [
        "durable terminal decision with evidence path",
        "no reopen unless new source, fixture, smoke, or callgraph evidence appears",
    ]


def _source_evidence(row: dict[str, Any], queue_blockers: dict[str, dict[str, Any]]) -> dict[str, Any]:
    blocker = queue_blockers.get(str(row.get("blocker_id") or ""), {})
    detector_path = ROOT / str(row.get("detector_path") or "")
    dsl = str(blocker.get("dsl_source_path") or "")
    dsl_path = ROOT / dsl if dsl else None
    return {
        "detector_path": str(row.get("detector_path") or ""),
        "detector_exists": detector_path.is_file(),
        "detector_sha256": _sha256(detector_path),
        "dsl_source_path": dsl,
        "dsl_source_exists": bool(dsl_path and dsl_path.is_file()),
        "claim_labels": list(row.get("claim_labels") or blocker.get("claim_labels") or []),
        "candidate_family": str(row.get("candidate_family") or blocker.get("candidate_family") or ""),
        "source_excerpt": str(blocker.get("source_excerpt") or "")[:360],
    }


def _fixture_paths(row: dict[str, Any]) -> dict[str, str]:
    paths = [str(item) for item in row.get("evidence") or [] if isinstance(item, str)]
    vulnerable = [path for path in paths if path.endswith("_vulnerable.sol") or path.endswith("_positive.sol")]
    clean = [path for path in paths if path.endswith("_clean.sol") or path.endswith("_negative.sol")]
    return {
        "vulnerable_fixture": vulnerable[0] if vulnerable else "",
        "clean_fixture": clean[0] if clean else "",
    }


def _durable_fixture_evidence(row: dict[str, Any], smoke: dict[str, Any]) -> dict[str, Any]:
    fixtures = _fixture_paths(row)
    return {
        "schema": FIXTURE_EVIDENCE_SCHEMA_VERSION,
        "task_id": row.get("task_id", ""),
        "blocker_id": row.get("blocker_id", ""),
        "detector_argument": row.get("detector_argument", ""),
        "detector_path": row.get("detector_path", ""),
        "fixture_evidence_status": "terminal_clean_positive_fixture_smoke",
        "evidence_class": SCAFFOLDED_EVIDENCE_CLASS,
        "callgraph_claim": "not_proved",
        "callgraph_overclaim_allowed": False,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "severity": "none",
        "selected_impact": "",
        "vulnerable_fixture": fixtures["vulnerable_fixture"],
        "clean_fixture": fixtures["clean_fixture"],
        "vulnerable_hits": smoke.get("vulnerable_hits"),
        "clean_hits": smoke.get("clean_hits"),
        "vulnerable_log": smoke.get("vulnerable_log", ""),
        "clean_log": smoke.get("clean_log", ""),
        "vulnerable_log_sha256": smoke.get("vulnerable_log_sha256", ""),
        "clean_log_sha256": smoke.get("clean_log_sha256", ""),
        "vulnerable_command_hint": smoke.get("vulnerable_command_hint", ""),
        "clean_command_hint": smoke.get("clean_command_hint", ""),
        "limitations": SOURCE_SHAPE_LIMITATIONS,
        "next_required_evidence": [
            "detector-lint callgraph/prose blocker cleared for this detector",
            "detector rewrite backed by accepted callgraph predicate or narrowed local-only claim",
            "separate impact and submission gates before any severity or filing posture",
        ],
    }


def _convert_row(
    row: dict[str, Any],
    *,
    smoke_log_dir: Path,
    queue_blockers: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    out = dict(row)
    original_status = str(row.get("execution_status") or "")
    out.update(
        {
            "conversion_worker": "DJ",
            "conversion_schema": SCHEMA_VERSION,
            "coverage_claim": "none_terminal_conversion_only",
            "evidence_class": GENERATED_EVIDENCE_CLASS,
            "promotion_allowed": False,
            "submission_posture": "NOT_SUBMIT_READY",
            "severity": "none",
            "selected_impact": "",
            "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
            "source_evidence": _source_evidence(row, queue_blockers),
            "blocking_axis": _blocking_axis(row),
            "required_evidence_to_reopen": _required_evidence(row),
        }
    )

    if original_status == "terminal_blocker_fixture_pair_present_smoke_blocked":
        smoke = _smoke_logs_for(row, smoke_log_dir)
        out["smoke_evidence"] = smoke
        if smoke["passed"]:
            durable_evidence = _durable_fixture_evidence(row, smoke)
            out["conversion_status"] = "converted_detector_fixture_smoked"
            out["terminal_decision"] = "fixture_pair_landed_and_smoked"
            out["blocker_reason"] = (
                "isolated detector smoke passed for the paired fixtures "
                "(vulnerable hits >= 1, clean hits == 0); callgraph/prose lint closure still requires "
                "a detector callgraph predicate or narrowed claim."
            )
            out["evidence"] = list(row.get("evidence") or []) + [
                f"vulnerable smoke hits={smoke['vulnerable_hits']}: {smoke['vulnerable_log']}",
                f"clean smoke hits={smoke['clean_hits']}: {smoke['clean_log']}",
            ]
            out["durable_fixture_evidence"] = durable_evidence
        else:
            out["conversion_status"] = "terminal_fixture_smoke_still_blocked"
    elif original_status == "auto_satisfied_existing_semantic_graph":
        out["conversion_status"] = "converted_semantic_source_shape_evidence"
        out["required_evidence_to_reopen"] = [
            "detector rewrite that consumes the semantic relation/path evidence",
            "paired detector fixture smoke",
            "detector-lint callgraph/prose blocker cleared for this detector",
        ]
    elif original_status == "terminal_blocker":
        out["conversion_status"] = "enriched_terminal_blocker"
        out["terminal_blocker_enrichment"] = {
            "terminal_no_reopen_without_new_evidence": True,
            "blocking_axis": out["blocking_axis"],
            "detector_source_recorded": out["source_evidence"]["detector_exists"],
            "required_evidence_count": len(out["required_evidence_to_reopen"]),
        }
    elif original_status == "terminal_decision_recorded":
        out["conversion_status"] = "terminal_decision_preserved"
        out["terminal_blocker_enrichment"] = {
            "terminal_no_reopen_without_new_evidence": True,
            "blocking_axis": out["blocking_axis"],
        }
    else:
        out["conversion_status"] = "unchanged_unclassified_execution_status"
    return out


def build_conversion(
    *,
    execution_path: Path,
    queue_path: Path,
    smoke_log_dir: Path,
) -> dict[str, Any]:
    execution = _read_json(execution_path)
    queue = _read_json(queue_path)
    task_results = execution.get("task_results")
    if not isinstance(task_results, list):
        raise SystemExit("[callgraph-terminal-conversion] execution JSON missing task_results[]")
    blockers = {
        str(blocker.get("blocker_id") or ""): blocker
        for blocker in queue.get("blockers", [])
        if isinstance(blocker, dict)
    }
    rows = [
        _convert_row(row, smoke_log_dir=smoke_log_dir, queue_blockers=blockers)
        for row in task_results
        if isinstance(row, dict)
    ]
    status_counts = Counter(str(row.get("conversion_status") or "") for row in rows)
    original_counts = Counter(str(row.get("execution_status") or "") for row in rows)
    axis_counts = Counter(str(row.get("blocking_axis") or "") for row in rows)
    durable_fixture_evidence_rows = [
        row["durable_fixture_evidence"]
        for row in rows
        if isinstance(row.get("durable_fixture_evidence"), dict)
    ]
    return {
        "schema": SCHEMA_VERSION,
        "worker": "DJ",
        "source_execution": _safe_rel(execution_path),
        "source_queue": _safe_rel(queue_path),
        "smoke_log_dir": _safe_rel(smoke_log_dir),
        "coverage_claim": "none_terminal_conversion_only",
        "evidence_class": GENERATED_EVIDENCE_CLASS,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "target_task_range": "150-300",
        "rows_consumed": len(task_results),
        "conversion_count": len(rows),
        "original_execution_status_counts": dict(sorted(original_counts.items())),
        "conversion_status_counts": dict(sorted(status_counts.items())),
        "blocking_axis_counts": dict(sorted(axis_counts.items())),
        "durable_fixture_evidence_count": len(durable_fixture_evidence_rows),
        "durable_fixture_evidence_rows": durable_fixture_evidence_rows,
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
        "rows": rows,
    }


def fixture_evidence_payload(conversion: dict[str, Any]) -> dict[str, Any]:
    rows = list(conversion.get("durable_fixture_evidence_rows") or [])
    return {
        "schema": FIXTURE_EVIDENCE_SCHEMA_VERSION,
        "source_conversion": conversion.get("source_execution", ""),
        "worker": conversion.get("worker", "DJ"),
        "evidence_count": len(rows),
        "coverage_claim": "none_fixture_smoke_only",
        "evidence_class": SCAFFOLDED_EVIDENCE_CLASS,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "severity": "none",
        "selected_impact": "",
        "callgraph_overclaim_allowed": False,
        "rows": rows,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Callgraph Terminal Conversion",
        "",
        "Advisory Worker DJ conversion of callgraph limitation execution rows.",
        "Rows are not findings, not severity approvals, and not promotion-ready.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- source execution: `{payload['source_execution']}`",
        f"- rows consumed: {payload['rows_consumed']}",
        f"- conversions: {payload['conversion_count']}",
        f"- durable fixture smoke rows: {payload.get('durable_fixture_evidence_count', 0)}",
        f"- promotion allowed: `{str(payload['promotion_allowed']).lower()}`",
        f"- posture: `{payload['submission_posture']}`",
        "",
        "## Conversion Counts",
        "",
    ]
    for key, value in payload.get("conversion_status_counts", {}).items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Blocking Axis Counts", ""])
    for key, value in payload.get("blocking_axis_counts", {}).items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Source-Shape Limitations", ""])
    for limitation in payload.get("source_shape_limitations", []):
        lines.append(f"- {limitation}")

    rows = payload.get("rows") if isinstance(payload.get("rows"), list) else []
    lines.extend(["", "## Converted Rows", ""])
    lines.append("| Task | Conversion | Axis | Detector | Decision | Evidence |")
    lines.append("|---|---|---|---|---|---|")
    for row in rows:
        evidence = list(row.get("evidence") or [])
        smoke = row.get("smoke_evidence") if isinstance(row.get("smoke_evidence"), dict) else {}
        if smoke.get("passed"):
            evidence = [
                f"vuln hits={smoke.get('vulnerable_hits')} `{smoke.get('vulnerable_log')}`",
                f"clean hits={smoke.get('clean_hits')} `{smoke.get('clean_log')}`",
            ]
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | {} |".format(
                row.get("task_id", ""),
                row.get("conversion_status", ""),
                row.get("blocking_axis", ""),
                row.get("detector_argument", ""),
                row.get("terminal_decision", ""),
                "<br>".join(str(item) for item in evidence[:3]),
            )
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execution",
        type=Path,
        default=ROOT / ".auditooor" / "callgraph_limitation_execution_de.json",
    )
    parser.add_argument(
        "--queue",
        type=Path,
        default=ROOT / ".auditooor" / "callgraph_limitation_queue.json",
    )
    parser.add_argument(
        "--smoke-log-dir",
        type=Path,
        default=ROOT / ".auditooor" / "command_logs" / "callgraph_dj",
    )
    parser.add_argument(
        "--out-json",
        type=Path,
        default=ROOT / ".auditooor" / "callgraph_terminal_conversion_dj.json",
    )
    parser.add_argument(
        "--out-md",
        type=Path,
        default=ROOT / ".auditooor" / "callgraph_terminal_conversion_dj.md",
    )
    parser.add_argument(
        "--out-fixture-evidence-json",
        type=Path,
        default=ROOT / ".auditooor" / "callgraph_fixture_smoke_evidence_dj.json",
    )
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    payload = build_conversion(
        execution_path=args.execution,
        queue_path=args.queue,
        smoke_log_dir=args.smoke_log_dir,
    )
    if payload["conversion_count"] < 150 or payload["conversion_count"] > 300:
        raise SystemExit(
            "[callgraph-terminal-conversion] conversion_count outside target range "
            f"150-300: {payload['conversion_count']}"
        )
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.out_md.write_text(render_markdown(payload), encoding="utf-8")
    args.out_fixture_evidence_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_fixture_evidence_json.write_text(
        json.dumps(fixture_evidence_payload(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[callgraph-terminal-conversion] OK "
        f"rows={payload['conversion_count']} statuses={payload['conversion_status_counts']} "
        f"json={args.out_json}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
