#!/usr/bin/env python3
"""Validate Runtime/DLT evidence without upgrading killed harnesses to proof.

The validator is intentionally conservative:
* killed / closed harness records become terminal evidence rows;
* blocked queue rows remain NOT_SUBMIT_READY blockers;
* recorded proved rows only promote when they map to an exact impact class and
  cite production/runtime proof sources, never mock/unit/static evidence;
* poc_execution manifests only promote with final_result=proved,
  impact_assertion=exploit_impact, evidence_class=executed_with_manifest,
  and a structured passing command row with a non-empty command.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from execution_manifest_proof import is_strict_proved_execution_manifest  # noqa: E402


SCHEMA = "auditooor.pr560.runtime_dlt_execution_evidence_validator.v3"
DEFAULT_OUT_JSON = ".auditooor/runtime_dlt_execution_evidence_validator.json"
DEFAULT_OUT_MD = ".auditooor/runtime_dlt_execution_evidence_validator.md"
DEFAULT_SUMMARY = ".auditooor/loop5_runtime_dlt_evidence_summary.json"
DEFAULT_BLOCKERS = ".auditooor/rust_runtime_semantic_blockers.json"
DEFAULT_RECORDS = ".auditooor/runtime_dlt_evidence_records.jsonl"
DEFAULT_IMPACT_MATRIX = "critical_hunt/wave5_impact_class_search/impact_class_matrix.json"
QUEUE_CANDIDATES = (
    ".auditooor/impact_miss_harness_blocker_queue.json",
    ".auditooor/loop5_preflight/impact_miss_harness_blocker_queue.json",
)
DLT_ROUTE_FAMILIES = {"node_liveness", "resource_consumption", "consensus_safety"}
TERMINAL_POSTURE_PREFIXES = ("killed", "closed_as")
RECORD_STATUSES = {"proved", "rejected", "blocked"}
IMPACT_ASSERTIONS = {"exploit_impact", "not_demonstrated", "unknown"}
PROMOTABLE_PROOF_SOURCES = {
    "production_replay",
    "runtime_integration",
    "live_component",
    "multi_client_differential",
}
NON_PROMOTABLE_PROOF_SOURCES = {
    "mock_harness",
    "unit_harness",
    "static_analysis",
    "scanner",
    "manual_triage",
}
PROOF_BOUNDARY = (
    "Runtime/DLT evidence rows are terminal triage or readiness evidence only. "
    "Killed harnesses can close a lane as not reportable, but they are not "
    "exploit proof. Runtime rows may only become promotion evidence when "
    "they map to an exact program impact class and use production/runtime "
    "proof sources rather than mock, unit, static-analysis, or scanner-only "
    "evidence. PoC execution manifests still require final_result=proved, "
    "impact_assertion=exploit_impact, evidence_class=executed_with_manifest, "
    "and structured status=pass/exit_code=0 command evidence."
)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def upsert_jsonl_by_id(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload_id = str(payload.get("id") or "")
    rows = [row for row in read_jsonl(path) if str(row.get("id") or "") != payload_id]
    rows.append(payload)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def resolve_existing(workspace: Path, candidates: tuple[str, ...]) -> Path | None:
    for candidate in candidates:
        path = workspace / candidate
        if path.is_file():
            return path
    return None


def artifact_exists(workspace: Path, ref: str) -> bool:
    path = Path(ref)
    if not path.is_absolute():
        path = workspace / path
    return path.exists()


def load_impact_matrix(path: Path) -> dict[str, dict[str, Any]]:
    payload = read_json(path)
    rows = payload.get("rows") or []
    matrix: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        row_id = str(row.get("row_id") or "").strip()
        if not row_id:
            continue
        impact_text = str(row.get("impact_text_verbatim") or "").strip()
        rubric_anchor = str(row.get("rubric_anchor") or "").strip()
        severity = "unknown"
        for tier in ("Critical", "High", "Medium", "Low"):
            if tier.lower() in rubric_anchor.lower():
                severity = tier
                break
        matrix[row_id] = {
            "impact_class": row_id,
            "impact_text": impact_text,
            "rubric_anchor": rubric_anchor,
            "severity": severity,
            "status": str(row.get("status") or ""),
            "proof_required": str(row.get("proof_required") or ""),
        }
    return matrix


def artifact_status(workspace: Path, artifacts: list[str]) -> dict[str, int]:
    return {
        "present": sum(1 for path in artifacts if artifact_exists(workspace, path)),
        "total": len(artifacts),
    }


def loop5_terminal_rows(workspace: Path, summary: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in summary.get("evidence_records") or []:
        if not isinstance(item, dict):
            continue
        posture = str(item.get("posture") or "")
        if not posture.startswith(TERMINAL_POSTURE_PREFIXES):
            continue
        artifacts = [str(path) for path in item.get("primary_artifacts") or []]
        rows.append(
            {
                "id": str(item.get("id") or ""),
                "source": "loop5_runtime_dlt_evidence_summary",
                "lane": item.get("lane"),
                "route_family": item.get("lane"),
                "status": "terminal_not_reportable",
                "terminal": True,
                "terminal_reason": posture,
                "basis": item.get("basis"),
                "artifact_paths": artifacts,
                "artifact_status": artifact_status(workspace, artifacts),
                "proof_class": "killed_harness_or_triage_evidence",
                "impact_assertion": "not_demonstrated",
                "promotion_allowed": False,
                "submission_posture": "NOT_SUBMIT_READY",
                "proof_boundary": PROOF_BOUNDARY,
            }
        )
    return rows


def dlt_queue_rows(queue: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in queue.get("rows") or []:
        if not isinstance(item, dict):
            continue
        route_family = str(item.get("route_family") or "")
        runtime_dep = item.get("runtime_semantic_dependency")
        has_runtime_dep = isinstance(runtime_dep, dict) and bool(runtime_dep)
        if route_family not in DLT_ROUTE_FAMILIES and not has_runtime_dep:
            continue
        rows.append(
            {
                "id": str(item.get("benchmark_id") or item.get("task_id") or ""),
                "source": "impact_miss_harness_blocker_queue",
                "task_id": item.get("task_id"),
                "tier": item.get("tier"),
                "route_family": route_family,
                "status": item.get("status") or "blocked_missing_artifacts",
                "terminal": False,
                "missing_artifacts": item.get("missing_artifacts") or [],
                "runtime_semantic_dependency": runtime_dep or {},
                "proof_class": "blocked_readiness_gate",
                "impact_assertion": "unknown",
                "promotion_allowed": False,
                "submission_posture": "NOT_SUBMIT_READY",
                "proof_boundary": PROOF_BOUNDARY,
            }
        )
    return rows


def normalize_impact_class(value: str) -> str:
    value = value.strip()
    if value.lower().startswith("row:"):
        value = value.split(":", 1)[1].strip()
    return value


def classify_record(
    workspace: Path,
    record: dict[str, Any],
    impact_matrix: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    status = str(record.get("status") or "").strip()
    impact_assertion = str(record.get("impact_assertion") or "").strip() or "unknown"
    proof_source = str(record.get("proof_source") or "").strip()
    artifacts = [str(path) for path in record.get("artifact_paths") or []]
    impact_class = normalize_impact_class(str(record.get("impact_class") or ""))
    mapped_impact = impact_matrix.get(impact_class, {}) if impact_class else {}
    blockers: list[str] = []

    if status not in RECORD_STATUSES:
        blockers.append("invalid_status")
    if impact_assertion not in IMPACT_ASSERTIONS:
        blockers.append("invalid_impact_assertion")
    if not impact_class:
        blockers.append("missing_impact_class")
    elif not mapped_impact:
        blockers.append("impact_class_not_in_matrix")
    if not artifacts:
        blockers.append("missing_artifact")
    if artifact_status(workspace, artifacts)["present"] != len(artifacts):
        blockers.append("artifact_missing_on_disk")

    promotion_allowed = False
    proof_class = "runtime_dlt_record"
    if status == "proved":
        if impact_assertion != "exploit_impact":
            blockers.append("proved_requires_exploit_impact")
        if proof_source not in PROMOTABLE_PROOF_SOURCES:
            blockers.append("proved_requires_production_runtime_proof_source")
        if proof_source in NON_PROMOTABLE_PROOF_SOURCES:
            blockers.append("mock_unit_static_or_scanner_evidence_cannot_promote")
        if not blockers:
            promotion_allowed = True
            proof_class = "mapped_runtime_exploit_proof"
        else:
            proof_class = "proved_claim_blocked_by_promotion_gate"
    elif status == "rejected":
        proof_class = "rejected_runtime_candidate"
    elif status == "blocked":
        proof_class = "blocked_runtime_candidate"

    return {
        **record,
        "id": str(record.get("id") or ""),
        "source": "runtime_dlt_evidence_records",
        "status": status,
        "terminal": status in {"proved", "rejected"},
        "route_family": str(record.get("route_family") or ""),
        "impact_class": impact_class,
        "mapped_impact": mapped_impact,
        "proof_source": proof_source,
        "artifact_paths": artifacts,
        "artifact_status": artifact_status(workspace, artifacts),
        "proof_class": proof_class,
        "promotion_allowed": promotion_allowed,
        "promotion_blockers": sorted(set(blockers)),
        "submission_posture": "SUBMIT_READY" if promotion_allowed else "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
    }


def runtime_record_rows(
    workspace: Path,
    records_path: Path,
    impact_matrix: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in read_jsonl(records_path):
        rows.append(classify_record(workspace, record, impact_matrix))
    return rows


def proved_exploit_manifest_count(workspace: Path) -> int:
    root = workspace / "poc_execution"
    if not root.is_dir():
        return 0
    count = 0
    for path in root.glob("*/execution_manifest.json"):
        payload = read_json(path)
        if is_strict_proved_execution_manifest(payload):
            count += 1
    return count


def build_record(args: argparse.Namespace, workspace: Path, impact_matrix: dict[str, dict[str, Any]]) -> dict[str, Any]:
    artifacts = [str(path) for path in args.artifact or []]
    record = {
        "schema": "auditooor.runtime_dlt_evidence_record.v1",
        "recorded_at": now_iso(),
        "workspace": str(workspace),
        "id": args.record_id,
        "candidate": args.candidate or "",
        "status": args.record_status,
        "route_family": args.route_family,
        "impact_class": normalize_impact_class(args.impact_class or ""),
        "impact_assertion": args.impact_assertion,
        "proof_source": args.proof_source,
        "artifact_paths": artifacts,
        "command": args.command or "",
        "notes": args.notes or "",
    }
    classified = classify_record(workspace, record, impact_matrix)
    if args.record_status == "proved" and classified["promotion_blockers"]:
        raise SystemExit(
            "refusing proved Runtime/DLT record: "
            + ", ".join(classified["promotion_blockers"])
        )
    return record


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Runtime/DLT Execution Evidence Validator",
        "",
        f"- DLT rows: `{payload['dlt_row_count']}`",
        f"- Terminal non-reportable rows: `{payload['terminal_not_reportable_count']}`",
        f"- Closure candidates: `{payload['closure_candidate_count']}`",
        f"- Proved exploit-impact manifests: `{payload['proved_exploit_impact_count']}`",
        f"- Mapped runtime proof rows: `{payload['mapped_runtime_proof_count']}`",
        f"- Submission posture: `{payload['submission_posture']}`",
        f"- Queue source: `{payload.get('queue_path') or 'not found'}`",
        f"- Evidence records: `{payload.get('records_path') or 'not found'}`",
        "",
        "## Summary",
        "",
        f"- Status counts: `{payload['summary']['status_counts']}`",
        f"- Route-family counts: `{payload['summary']['route_family_counts']}`",
        f"- Impact-class counts: `{payload['summary']['impact_class_counts']}`",
        "",
        "## Rows",
        "",
        "| ID | Source | Route/lane | Impact class | Status | Terminal | Proof class | Promotion blockers |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in payload["rows"][:300]:
        blockers = ", ".join(row.get("promotion_blockers") or [])
        lines.append(
            f"| `{row['id']}` | `{row['source']}` | `{row.get('route_family') or ''}` | "
            f"`{row.get('impact_class') or ''}` | `{row['status']}` | `{row['terminal']}` | "
            f"`{row['proof_class']}` | `{blockers}` |"
        )
    lines.extend(["", "## Proof Boundary", "", payload["proof_boundary"]])
    return "\n".join(lines).rstrip() + "\n"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--queue", type=Path, help="Impact-Miss queue JSON")
    parser.add_argument("--summary", type=Path, help=f"Loop 5 summary JSON; default {DEFAULT_SUMMARY}")
    parser.add_argument("--runtime-blockers", type=Path, help=f"Runtime blocker JSON; default {DEFAULT_BLOCKERS}")
    parser.add_argument("--records-jsonl", type=Path, help=f"Runtime/DLT evidence ledger; default {DEFAULT_RECORDS}")
    parser.add_argument("--impact-matrix", type=Path, help=f"Impact-class matrix JSON; default {DEFAULT_IMPACT_MATRIX}")
    parser.add_argument("--out-json", type=Path, help=f"Output JSON; default {DEFAULT_OUT_JSON}")
    parser.add_argument("--out-md", type=Path, help=f"Output Markdown; default {DEFAULT_OUT_MD}")
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument("--record-id", help="Append or update one runtime/DLT evidence record with this stable ID")
    parser.add_argument("--record-status", choices=sorted(RECORD_STATUSES), help="Record status")
    parser.add_argument("--candidate", help="Candidate/finding ID for --record-id")
    parser.add_argument("--route-family", default="", help="Runtime route family, e.g. consensus_safety")
    parser.add_argument("--impact-class", help="Impact matrix row_id, e.g. 2 for BDL-C2")
    parser.add_argument("--impact-assertion", choices=sorted(IMPACT_ASSERTIONS), default="unknown")
    parser.add_argument(
        "--proof-source",
        choices=sorted(PROMOTABLE_PROOF_SOURCES | NON_PROMOTABLE_PROOF_SOURCES),
        default="manual_triage",
    )
    parser.add_argument("--artifact", action="append", help="Artifact path supporting the record; repeatable")
    parser.add_argument("--command", help="Exact command used to produce or validate the evidence")
    parser.add_argument("--notes", help="Short evidence note or blocker explanation")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    queue_path = args.queue.expanduser().resolve() if args.queue else resolve_existing(workspace, QUEUE_CANDIDATES)
    summary_path = (args.summary or workspace / DEFAULT_SUMMARY).expanduser().resolve()
    blockers_path = (args.runtime_blockers or workspace / DEFAULT_BLOCKERS).expanduser().resolve()
    records_path = (args.records_jsonl or workspace / DEFAULT_RECORDS).expanduser().resolve()
    impact_matrix_path = (args.impact_matrix or workspace / DEFAULT_IMPACT_MATRIX).expanduser().resolve()
    impact_matrix = load_impact_matrix(impact_matrix_path)

    if args.record_id:
        if not args.record_status:
            raise SystemExit("--record-status is required with --record-id")
        record = build_record(args, workspace, impact_matrix)
        upsert_jsonl_by_id(records_path, record)

    summary = read_json(summary_path)
    queue = read_json(queue_path) if queue_path else {}
    blockers = read_json(blockers_path)
    rows = (
        loop5_terminal_rows(workspace, summary)
        + dlt_queue_rows(queue)
        + runtime_record_rows(workspace, records_path, impact_matrix)
    )
    proved_count = proved_exploit_manifest_count(workspace)
    mapped_runtime_proof_count = sum(1 for row in rows if row.get("proof_class") == "mapped_runtime_exploit_proof")
    status_counts = Counter(str(row.get("status") or "") for row in rows)
    route_counts = Counter(str(row.get("route_family") or "") for row in rows)
    impact_class_counts = Counter(str(row.get("impact_class") or "") for row in rows if row.get("impact_class"))
    terminal_count = sum(1 for row in rows if row.get("terminal"))
    closure_candidate_count = sum(1 for row in rows if row.get("terminal") and row.get("status") != "terminal_not_reportable")
    promotion_allowed = proved_count > 0 or mapped_runtime_proof_count > 0
    payload = {
        "schema": SCHEMA,
        "generated_at": now_iso(),
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "queue_path": str(queue_path) if queue_path else None,
        "summary_source": str(summary_path),
        "runtime_blockers_path": str(blockers_path),
        "records_path": str(records_path),
        "impact_matrix_path": str(impact_matrix_path),
        "dlt_row_count": len(rows),
        "terminal_not_reportable_count": terminal_count,
        "closure_candidate_count": closure_candidate_count,
        "proved_exploit_impact_count": proved_count,
        "mapped_runtime_proof_count": mapped_runtime_proof_count,
        "promotion_allowed": promotion_allowed,
        "submission_posture": "SUBMIT_READY" if promotion_allowed else "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "summary": {
            "status_counts": dict(sorted(status_counts.items())),
            "route_family_counts": dict(sorted(route_counts.items())),
            "impact_class_counts": dict(sorted(impact_class_counts.items())),
            "runtime_component_family_counts": blockers.get("runtime_component_family_counts")
            or blockers.get("summary", {}).get("runtime_component_family_counts")
            or {},
        },
        "rows": rows,
    }
    out_json = (args.out_json or workspace / DEFAULT_OUT_JSON).expanduser().resolve()
    out_md = (args.out_md or workspace / DEFAULT_OUT_MD).expanduser().resolve()
    write_json(out_json, payload)
    write_text(out_md, render_markdown(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[runtime-dlt-validator] wrote {len(rows)} rows -> {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
