#!/usr/bin/env python3
"""Turn validated project-source roots into source/harness review work units.

This is intentionally one step below proof.  It consumes
``project-source-root-readiness`` and ``impact-binding-source-harness-discovery``
and, when a real target project root is available, emits line-level candidate
hits that a human or follow-up proof tool can review.  Generated fixtures and
Auditooor-owned files are not accepted as project source.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.pr560.impact_binding_source_import_readiness.v1"
DEFAULT_DISCOVERY = ".auditooor/impact_binding_source_harness_discovery.json"
DEFAULT_READINESS = ".auditooor/project_source_root_readiness.json"
DEFAULT_OUT = ".auditooor/impact_binding_source_import_readiness.json"
DEFAULT_OUT_MD = ".auditooor/impact_binding_source_import_readiness.md"
DEFAULT_BUNDLE_DIR = ".auditooor/impact_binding_source_import_bundles"
WORKER_LEDGER_JSON = ".auditooor/pr560_worker_impact_binding_source_import_readiness.json"
WORKER_LEDGER_MD = ".auditooor/pr560_worker_impact_binding_source_import_readiness.md"
PROOF_BOUNDARY = (
    "Source-import readiness is review evidence only. It does not prove source "
    "reachability, listed impact, exploit impact, severity, OOS status, "
    "production path, or submission readiness."
)
FAMILY_KEYWORDS = {
    "access_control": ["access", "auth", "authorize", "owner", "role", "permission"],
    "asset_custody": ["asset", "custody", "vault", "withdraw", "deposit", "transfer"],
    "availability_dos": ["availability", "dos", "pause", "liveness", "halt"],
    "bridge_finalization": ["bridge", "finalize", "withdrawal", "message", "root"],
    "consensus_safety": ["consensus", "validator", "attest", "fork", "payload"],
    "governance_integrity": ["governance", "proposal", "vote", "timelock", "delegate"],
    "liquidation_solvency": ["liquidation", "solvency", "debt", "collateral", "health"],
    "node_liveness": ["node", "liveness", "p2p", "gossip", "engine"],
    "oracle_settlement": ["oracle", "settle", "price", "answer", "round"],
    "proof_verification": ["proof", "verify", "verifier", "zk", "fraud"],
    "resource_consumption": ["resource", "gas", "memory", "cpu", "decode"],
    "signature_replay": ["signature", "replay", "nonce", "permit", "domain"],
}
SOURCE_SUFFIXES = {".sol", ".rs", ".move", ".cairo", ".vy"}


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[source-import-readiness] ERR invalid JSON in {path}: {exc}") from None


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def workspace_relative(workspace: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def keywords_for(route_family: str, candidate_id: str) -> list[str]:
    tokens = set(FAMILY_KEYWORDS.get(route_family, []))
    tokens.update(part for part in route_family.split("_") if len(part) > 2)
    for part in re.split(r"[^a-zA-Z0-9]+", candidate_id):
        lowered = part.lower()
        if lowered and lowered not in {"imo", "critical", "high", "medium", "low"} and not lowered.isdigit():
            tokens.add(lowered)
    return sorted(tokens)


def ready_source_files(readiness: dict[str, Any]) -> list[dict[str, Any]]:
    files: dict[str, dict[str, Any]] = {}
    for root in readiness.get("roots") or []:
        if not isinstance(root, dict) or not root.get("usable"):
            continue
        for item in root.get("sample_files") or []:
            if not isinstance(item, dict):
                continue
            file_text = str(item.get("file") or "")
            if Path(file_text).suffix not in SOURCE_SUFFIXES:
                continue
            files.setdefault(
                file_text,
                {
                    "file": file_text,
                    "abs_path": str(item.get("abs_path") or ""),
                    "root_label": str(root.get("label") or ""),
                },
            )
    return [files[key] for key in sorted(files)]


def line_hits(workspace: Path, source: dict[str, Any], keywords: list[str], *, max_hits: int = 20) -> list[dict[str, Any]]:
    path = Path(str(source.get("abs_path") or ""))
    if not path.is_absolute():
        path = workspace / str(source.get("file") or "")
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    hits: list[dict[str, Any]] = []
    lowered_keywords = [(keyword, keyword.lower()) for keyword in keywords if len(keyword) >= 3]
    for line_no, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()
        matched = [original for original, lowered_keyword in lowered_keywords if lowered_keyword in lowered]
        if not matched:
            continue
        hits.append(
            {
                "file": str(source.get("file") or workspace_relative(workspace, path)),
                "line": line_no,
                "matched_keywords": matched[:12],
                "snippet": line.strip()[:240],
                "proof_posture": "candidate_line_hit_not_source_proof",
            }
        )
        if len(hits) >= max_hits:
            break
    return hits


def classify(row: dict[str, Any], source_files: list[dict[str, Any]], workspace: Path) -> dict[str, Any]:
    candidate_id = str(row.get("candidate_id") or "")
    route_family = str(row.get("route_family") or "")
    requirement = str(row.get("requirement") or "")
    keywords = keywords_for(route_family, candidate_id)
    hits = [hit for source in source_files for hit in line_hits(workspace, source, keywords)]
    hits = hits[:25]
    if not source_files:
        status = "terminal_no_ready_project_source_roots"
        missing_inputs = ["project_source_root", "candidate_bound_project_source_citation"]
    elif not hits:
        status = "terminal_no_candidate_line_hits_in_project_source"
        missing_inputs = ["candidate_bound_project_source_citation"]
    elif requirement == "project_specific_harness_execution":
        status = "harness_binding_candidate_lines_found"
        missing_inputs = ["project_harness_binding", "impact_assertions", "poc_execution_record"]
    else:
        status = "source_review_candidate_lines_found"
        missing_inputs = ["manual_line_citation", "source_proof_record", "oos_clearance"]
    return {
        "candidate_id": candidate_id,
        "impact_contract_id": str(row.get("impact_contract_id") or ""),
        "route_family": route_family,
        "tier": str(row.get("tier") or ""),
        "requirement": requirement,
        "prior_discovery_status": str(row.get("discovery_status") or ""),
        "source_import_status": status,
        "ready_source_file_count": len(source_files),
        "line_hit_count": len(hits),
        "line_hits": hits,
        "missing_inputs": missing_inputs,
        "next_command": next_command(candidate_id, requirement, hits),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
    }


def next_command(candidate_id: str, requirement: str, hits: list[dict[str, Any]]) -> str:
    if not hits:
        return "declare/import real target project source roots, rerun readiness, then rerun source-import readiness"
    first = hits[0]
    citation = f"{first['file']}:{first['line']}"
    if requirement == "project_specific_harness_execution":
        return (
            f"bind candidate {candidate_id} harness to reviewed source around {citation}; "
            "run project setup and record with make poc-execution-record only after impact assertions pass"
        )
    return (
        f"review {citation}; if exact and in scope, run make source-proof-record "
        f"WS=<workspace> CANDIDATE={candidate_id} CITATION='{citation}' OOS=in_scope VERDICT=proved_source_only"
    )


def build_payload(
    workspace: Path,
    *,
    discovery_path: Path | None = None,
    readiness_path: Path | None = None,
    bundle_dir: Path | None = None,
) -> dict[str, Any]:
    discovery = load_json(discovery_path or workspace / DEFAULT_DISCOVERY)
    readiness = load_json(readiness_path or workspace / DEFAULT_READINESS)
    source_files = ready_source_files(readiness if isinstance(readiness, dict) else {})
    reductions = [
        classify(row, source_files, workspace)
        for row in discovery.get("reductions", [])
        if isinstance(row, dict)
        and row.get("requirement") in {"candidate_bound_project_source_citation", "project_specific_harness_execution"}
    ]
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in reductions:
        by_family[row["route_family"]].append(row)
    payload = {
        "schema": SCHEMA,
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "discovery_path": str(discovery_path or workspace / DEFAULT_DISCOVERY),
        "readiness_path": str(readiness_path or workspace / DEFAULT_READINESS),
        "ready_source_file_count": len(source_files),
        "input_reduction_count": len(discovery.get("reductions", []) if isinstance(discovery, dict) else []),
        "source_import_unit_count": len(reductions),
        "line_hit_unit_count": sum(1 for row in reductions if row["line_hit_count"]),
        "closure_candidate_count": 0,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "summary": {
            "source_import_status_counts": dict(sorted(Counter(row["source_import_status"] for row in reductions).items())),
            "requirement_counts": dict(sorted(Counter(row["requirement"] for row in reductions).items())),
            "route_family_counts": dict(sorted(Counter(row["route_family"] for row in reductions).items())),
            "missing_input_counts": dict(sorted(Counter(item for row in reductions for item in row["missing_inputs"]).items())),
        },
        "source_files": source_files[:200],
        "family_manifests": {
            family: {
                "unit_count": len(rows),
                "line_hit_units": sum(1 for row in rows if row["line_hit_count"]),
                "source_import_status_counts": dict(sorted(Counter(row["source_import_status"] for row in rows).items())),
                "promotion_allowed": False,
                "submission_posture": "NOT_SUBMIT_READY",
            }
            for family, rows in sorted(by_family.items())
        },
        "units": reductions,
    }
    if bundle_dir:
        bundle_dir.mkdir(parents=True, exist_ok=True)
        for family, rows in sorted(by_family.items()):
            write_json(
                bundle_dir / f"{family}.json",
                {
                    "schema": "auditooor.pr560.impact_binding_source_import_family.v1",
                    "workspace": str(workspace),
                    "route_family": family,
                    "unit_count": len(rows),
                    "line_hit_units": sum(1 for row in rows if row["line_hit_count"]),
                    "source_import_status_counts": dict(sorted(Counter(row["source_import_status"] for row in rows).items())),
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "proof_boundary": PROOF_BOUNDARY,
                    "units": rows,
                },
            )
    return payload


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Impact Binding Source Import Readiness",
        "",
        PROOF_BOUNDARY,
        "",
        "## Summary",
        "",
        f"- Source-import units: `{payload['source_import_unit_count']}`",
        f"- Ready source files: `{payload['ready_source_file_count']}`",
        f"- Units with line hits: `{payload['line_hit_unit_count']}`",
        f"- Closure candidates: `{payload['closure_candidate_count']}`",
        "",
        "## Status Counts",
        "",
    ]
    for key, value in payload["summary"]["source_import_status_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## First Units", ""])
    for row in payload["units"][:30]:
        lines.append(
            f"- `{row['candidate_id']}` / `{row['requirement']}`: "
            f"`{row['source_import_status']}` hits=`{row['line_hit_count']}` -> `{row['next_command']}`"
        )
    return "\n".join(lines)


def worker_ledger(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "auditooor.pr560.worker.impact_binding_source_import_readiness.v1",
        "generated_at_unix": payload["generated_at_unix"],
        "workspace": payload["workspace"],
        "changed_tool": "tools/impact-binding-source-import-readiness.py",
        "source_import_unit_count": payload["source_import_unit_count"],
        "ready_source_file_count": payload["ready_source_file_count"],
        "line_hit_unit_count": payload["line_hit_unit_count"],
        "closure_candidate_count": payload["closure_candidate_count"],
        "summary": payload["summary"],
        "blockers_left": [
            "real target project roots are required before source-import units can produce line hits",
            "line hits still require manual exact citation review and source-proof records",
            "harness hits still require project setup, impact assertions, and proved execution manifests",
        ],
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--discovery-json", type=Path)
    parser.add_argument("--readiness-json", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--worker-ledger-json", type=Path)
    parser.add_argument("--worker-ledger-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    payload = build_payload(
        workspace,
        discovery_path=(args.discovery_json.expanduser().resolve() if args.discovery_json else workspace / DEFAULT_DISCOVERY),
        readiness_path=(args.readiness_json.expanduser().resolve() if args.readiness_json else workspace / DEFAULT_READINESS),
        bundle_dir=(args.bundle_dir.expanduser().resolve() if args.bundle_dir else workspace / DEFAULT_BUNDLE_DIR),
    )
    out_json = (args.out_json or workspace / DEFAULT_OUT).expanduser().resolve()
    out_md = (args.out_md or workspace / DEFAULT_OUT_MD).expanduser().resolve()
    write_json(out_json, payload)
    write_text(out_md, render_markdown(payload))
    ledger = worker_ledger(payload)
    write_json((args.worker_ledger_json or workspace / WORKER_LEDGER_JSON).expanduser().resolve(), ledger)
    write_text((args.worker_ledger_md or workspace / WORKER_LEDGER_MD).expanduser().resolve(), render_markdown(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[source-import-readiness] OK "
        f"units={payload['source_import_unit_count']} ready_files={payload['ready_source_file_count']} "
        f"line_hit_units={payload['line_hit_unit_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
