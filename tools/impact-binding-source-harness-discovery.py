#!/usr/bin/env python3
"""Classify impact-binding source and harness units against project sources.

This is one layer after ``impact-binding-next-input-validator.py``.  It turns
open-ended "search project source" and "replace neutral harness" work into
workspace-local, machine-readable states.  Generated fixtures, reference kits,
detectors, reports, and Auditooor scaffolds are deliberately excluded from
project-source evidence so this tool cannot accidentally promote benchmark
material as candidate-bound proof.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.pr560.impact_binding_source_harness_discovery.v1"
DEFAULT_INPUT = ".auditooor/impact_binding_next_input_validator.json"
DEFAULT_SEMANTIC_GRAPH = ".auditooor/semantic_graph.json"
DEFAULT_PROJECT_SOURCE_READINESS = ".auditooor/project_source_root_readiness.json"
DEFAULT_OUT = ".auditooor/impact_binding_source_harness_discovery.json"
DEFAULT_OUT_MD = ".auditooor/impact_binding_source_harness_discovery.md"
DEFAULT_BUNDLE_DIR = ".auditooor/impact_binding_source_harness_bundles"
WORKER_LEDGER_JSON = ".auditooor/pr560_worker_impact_binding_source_harness_discovery.json"
WORKER_LEDGER_MD = ".auditooor/pr560_worker_impact_binding_source_harness_discovery.md"
PROOF_BOUNDARY = (
    "Discovery rows are source/harness binding reducers only. They do not prove "
    "listed impact, set severity, prove source reachability, prove exploit "
    "impact, or authorize submission."
)

SOURCE_SUFFIXES = {".sol", ".rs", ".move", ".cairo", ".vy", ".go", ".ts", ".nr"}  # r36-rebuttal: bugfix-inventory-claude-20260610
EXCLUDED_PREFIXES = (
    ".auditooor/",
    ".audit_logs/",
    ".github/",
    "benchmark_fixtures/",
    "detectors/",
    "docs/",
    "examples/",
    "monitoring/",
    "patterns/",
    "poc-tests/",
    "reference/",
    "reports/",
    "source_proofs/",
    "templates/",
    "test_fixtures/",
    "tests/",
    "tools/",
)
EXCLUDED_PARTS = {".git", "node_modules", "vendor", "lib", "__pycache__", "submissions", "test_poc", "pocs"}
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


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[impact-binding-discovery] ERR invalid JSON in {path}: {exc}") from None


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def is_project_source_path(path_text: str) -> bool:
    if not path_text:
        return False
    path = Path(path_text)
    normalized = path_text.replace("\\", "/").lstrip("./")
    if path.suffix not in SOURCE_SUFFIXES:
        return False
    if any(normalized.startswith(prefix) for prefix in EXCLUDED_PREFIXES):
        return False
    if any(part in EXCLUDED_PARTS for part in path.parts):
        return False
    return True


def semantic_project_sources(workspace: Path, semantic_graph_path: Path) -> list[dict[str, Any]]:
    graph = load_json(semantic_graph_path)
    contracts = graph.get("contracts") if isinstance(graph, dict) else []
    sources: dict[str, dict[str, Any]] = {}
    for contract in contracts or []:
        if not isinstance(contract, dict):
            continue
        file_text = str(contract.get("file") or "")
        if not is_project_source_path(file_text):
            continue
        entry = sources.setdefault(
            file_text,
            {
                "file": file_text,
                "abs_path": str((workspace / file_text).resolve()),
                "contracts": [],
                "functions": [],
            },
        )
        contract_name = str(contract.get("name") or "")
        if contract_name:
            entry["contracts"].append(contract_name)
        for fn in contract.get("functions") or []:
            if isinstance(fn, dict) and fn.get("name"):
                entry["functions"].append(str(fn["name"]))
    return [sources[key] for key in sorted(sources)]


def readiness_project_sources(workspace: Path, readiness_path: Path) -> list[dict[str, Any]]:
    payload = load_json(readiness_path)
    roots = payload.get("roots") if isinstance(payload, dict) else []
    sources: dict[str, dict[str, Any]] = {}
    for root in roots or []:
        if not isinstance(root, dict) or not root.get("usable"):
            continue
        for item in root.get("sample_files") or []:
            if not isinstance(item, dict):
                continue
            file_text = str(item.get("file") or "")
            if not is_project_source_path(file_text):
                continue
            sources.setdefault(
                file_text,
                {
                    "file": file_text,
                    "abs_path": str(item.get("abs_path") or (workspace / file_text).resolve()),
                    "contracts": [],
                    "functions": [],
                    "source": "project_source_root_readiness",
                },
            )
    return [sources[key] for key in sorted(sources)]


def project_sources_for(
    workspace: Path,
    semantic_graph_path: Path,
    project_source_readiness_path: Path | None = None,
) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for source in semantic_project_sources(workspace, semantic_graph_path):
        merged[source["file"]] = {**source, "source": "semantic_graph"}
    if project_source_readiness_path:
        for source in readiness_project_sources(workspace, project_source_readiness_path):
            existing = merged.get(source["file"], {})
            merged[source["file"]] = {
                **source,
                "contracts": sorted(set((existing.get("contracts") or []) + (source.get("contracts") or []))),
                "functions": sorted(set((existing.get("functions") or []) + (source.get("functions") or []))),
                "source": ",".join(sorted(set(filter(None, [existing.get("source"), source.get("source")])))),
            }
    return [merged[key] for key in sorted(merged)]


def family_keywords(route_family: str, candidate_id: str) -> list[str]:
    tokens = set(FAMILY_KEYWORDS.get(route_family, []))
    tokens.update(part for part in route_family.split("_") if len(part) > 2)
    for part in re.split(r"[^a-zA-Z0-9]+", candidate_id):
        lowered = part.lower()
        if lowered and lowered not in {"imo", "critical", "high", "medium", "low"} and not lowered.isdigit():
            tokens.add(lowered)
    return sorted(tokens)


def match_sources(unit: dict[str, Any], project_sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    route_family = str(unit.get("route_family") or "")
    candidate = str(unit.get("candidate_id") or "")
    keywords = family_keywords(route_family, candidate)
    matches: list[dict[str, Any]] = []
    for source in project_sources:
        haystack = " ".join(
            [
                str(source.get("file") or ""),
                " ".join(source.get("contracts") or []),
                " ".join(source.get("functions") or []),
            ]
        ).lower()
        hits = [keyword for keyword in keywords if keyword and keyword.lower() in haystack]
        if hits:
            matches.append(
                {
                    "file": source["file"],
                    "contracts": sorted(set(source.get("contracts") or [])),
                    "functions": sorted(set(source.get("functions") or []))[:25],
                    "matched_keywords": hits[:20],
                    "proof_posture": "candidate_binding_hint_not_source_proof",
                }
            )
    return matches[:10]


def classify_source_unit(unit: dict[str, Any], project_sources: list[dict[str, Any]]) -> dict[str, Any]:
    matches = match_sources(unit, project_sources)
    if not project_sources:
        status = "terminal_no_project_source_roots"
        missing_inputs = ["project_source_root", "candidate_bound_project_source_citation"]
    elif matches:
        status = "candidate_project_source_hints_require_manual_citation"
        missing_inputs = ["manual_line_citation", "source_proof_record", "oos_clearance"]
    else:
        status = "terminal_no_candidate_family_match_in_project_sources"
        missing_inputs = ["candidate_bound_project_source_citation"]
    return {
        **base_reduction(unit),
        "reduction_kind": "candidate_bound_source_discovery",
        "discovery_status": status,
        "project_source_root_count": len(project_sources),
        "candidate_source_hint_count": len(matches),
        "candidate_source_hints": matches,
        "missing_inputs": missing_inputs,
        "next_command": next_source_command(unit, matches),
    }


def classify_harness_unit(unit: dict[str, Any], project_sources: list[dict[str, Any]]) -> dict[str, Any]:
    matches = match_sources(unit, project_sources)
    local_status = unit.get("local_artifact_status") if isinstance(unit.get("local_artifact_status"), dict) else {}
    missing = [str(item) for item in local_status.get("missing_requirements") or unit.get("missing_inputs") or []]
    if not project_sources:
        status = "terminal_harness_blocked_no_project_source_roots"
        missing_inputs = sorted(set(missing + ["project_source_root", "target_project_binding"]))
    elif matches:
        status = "harness_binding_hints_require_project_setup"
        missing_inputs = sorted(set(missing + ["project_setup", "harness_assertions", "proved_execution_manifest"]))
    else:
        status = "terminal_harness_blocked_no_candidate_project_source_match"
        missing_inputs = sorted(set(missing + ["target_project_binding"]))
    return {
        **base_reduction(unit),
        "reduction_kind": "project_specific_harness_discovery",
        "discovery_status": status,
        "project_source_root_count": len(project_sources),
        "candidate_source_hint_count": len(matches),
        "candidate_source_hints": matches,
        "missing_inputs": missing_inputs,
        "next_command": next_harness_command(unit, matches),
    }


def base_reduction(unit: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidate_id": str(unit.get("candidate_id") or ""),
        "impact_contract_id": str(unit.get("impact_contract_id") or ""),
        "route_family": str(unit.get("route_family") or ""),
        "tier": str(unit.get("tier") or ""),
        "requirement": str(unit.get("requirement") or ""),
        "prior_blocker_class": str(unit.get("blocker_class") or ""),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
    }


def next_source_command(unit: dict[str, Any], matches: list[dict[str, Any]]) -> str:
    candidate = str(unit.get("candidate_id") or "")
    if matches:
        files = " ".join(match["file"] for match in matches[:3])
        return (
            f"review exact candidate lines in {files}; then make source-proof-record "
            f"WS=<workspace> CANDIDATE={candidate} CITATION='<project-source-file:line>' "
            "OOS=in_scope VERDICT=proved_source_only"
        )
    return "import or point WS at real project source roots, then rerun impact-binding-source-harness-discovery"


def next_harness_command(unit: dict[str, Any], matches: list[dict[str, Any]]) -> str:
    candidate = str(unit.get("candidate_id") or "")
    if matches:
        return (
            f"replace poc-tests/{candidate}/run_harness.sh neutral scaffold with project setup "
            "using candidate source hints; record with poc-execution-record only after impact assertions pass"
        )
    return "project-specific harness is blocked until candidate-bound project source/runtime roots are present"


def build_payload(
    workspace: Path,
    *,
    input_path: Path | None = None,
    semantic_graph_path: Path | None = None,
    project_source_readiness_path: Path | None = None,
    bundle_dir: Path | None = None,
) -> dict[str, Any]:
    input_payload = load_json(input_path or workspace / DEFAULT_INPUT)
    units = [unit for unit in input_payload.get("units") or [] if isinstance(unit, dict)]
    project_sources = project_sources_for(
        workspace,
        semantic_graph_path or workspace / DEFAULT_SEMANTIC_GRAPH,
        project_source_readiness_path,
    )
    reductions: list[dict[str, Any]] = []
    for unit in units:
        requirement = str(unit.get("requirement") or "")
        if requirement == "candidate_bound_project_source_citation":
            reductions.append(classify_source_unit(unit, project_sources))
        elif requirement == "project_specific_harness_execution":
            reductions.append(classify_harness_unit(unit, project_sources))

    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in reductions:
        by_family[row["route_family"]].append(row)

    terminal_rows = [
        row
        for row in reductions
        if str(row.get("discovery_status") or "").startswith("terminal_")
    ]
    hint_rows = [row for row in reductions if row.get("candidate_source_hint_count")]
    payload = {
        "schema": SCHEMA,
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "source_next_input_path": str(input_path or workspace / DEFAULT_INPUT),
        "semantic_graph_path": str(semantic_graph_path or workspace / DEFAULT_SEMANTIC_GRAPH),
        "project_source_readiness_path": str(project_source_readiness_path or ""),
        "project_source_root_count": len(project_sources),
        "project_sources": project_sources[:200],
        "input_unit_count": len(units),
        "reduced_unit_count": len(reductions),
        "terminal_reduced_unit_count": len(terminal_rows),
        "candidate_source_hint_unit_count": len(hint_rows),
        "closure_candidate_count": 0,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "summary": {
            "requirement_counts": dict(sorted(Counter(row["requirement"] for row in reductions).items())),
            "discovery_status_counts": dict(sorted(Counter(row["discovery_status"] for row in reductions).items())),
            "route_family_counts": dict(sorted(Counter(row["route_family"] for row in reductions).items())),
            "missing_input_counts": dict(sorted(Counter(item for row in reductions for item in row["missing_inputs"]).items())),
        },
        "family_manifests": {
            family: {
                "unit_count": len(rows),
                "discovery_status_counts": dict(sorted(Counter(row["discovery_status"] for row in rows).items())),
                "candidate_source_hint_units": sum(1 for row in rows if row.get("candidate_source_hint_count")),
                "promotion_allowed": False,
                "submission_posture": "NOT_SUBMIT_READY",
            }
            for family, rows in sorted(by_family.items())
        },
        "reductions": reductions,
    }

    if bundle_dir:
        bundle_dir.mkdir(parents=True, exist_ok=True)
        for family, rows in sorted(by_family.items()):
            write_json(
                bundle_dir / f"{family}.json",
                {
                    "schema": "auditooor.pr560.impact_binding_source_harness_family.v1",
                    "workspace": str(workspace),
                    "route_family": family,
                    "unit_count": len(rows),
                    "discovery_status_counts": dict(sorted(Counter(row["discovery_status"] for row in rows).items())),
                    "missing_input_counts": dict(sorted(Counter(item for row in rows for item in row["missing_inputs"]).items())),
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "proof_boundary": PROOF_BOUNDARY,
                    "reductions": rows,
                },
            )
    return payload


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Impact Binding Source/Harness Discovery",
        "",
        PROOF_BOUNDARY,
        "",
        "## Summary",
        "",
        f"- Input units: `{payload['input_unit_count']}`",
        f"- Source/harness units reduced: `{payload['reduced_unit_count']}`",
        f"- Terminal reduced units: `{payload['terminal_reduced_unit_count']}`",
        f"- Candidate source hint units: `{payload['candidate_source_hint_unit_count']}`",
        f"- Project source roots: `{payload['project_source_root_count']}`",
        f"- Closure candidates: `{payload['closure_candidate_count']}`",
        "",
        "## Discovery Status Counts",
        "",
    ]
    for key, value in payload["summary"]["discovery_status_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Missing Inputs", ""])
    for key, value in payload["summary"]["missing_input_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Route Families", ""])
    for key, value in payload["summary"]["route_family_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## First Reductions", ""])
    for row in payload["reductions"][:30]:
        lines.append(
            f"- `{row['candidate_id']}` / `{row['requirement']}`: "
            f"`{row['discovery_status']}` -> `{row['next_command']}`"
        )
    return "\n".join(lines)


def worker_ledger(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "auditooor.pr560.worker.impact_binding_source_harness_discovery.v1",
        "generated_at_unix": payload["generated_at_unix"],
        "workspace": payload["workspace"],
        "changed_tool": "tools/impact-binding-source-harness-discovery.py",
        "reduced_unit_count": payload["reduced_unit_count"],
        "terminal_reduced_unit_count": payload["terminal_reduced_unit_count"],
        "candidate_source_hint_unit_count": payload["candidate_source_hint_unit_count"],
        "closure_candidate_count": payload["closure_candidate_count"],
        "summary": payload["summary"],
        "blockers_left": [
            "candidate-bound project source roots/citations are still required before source proof promotion",
            "project-specific harness execution remains blocked until real target source/runtime bindings exist",
            "proved exploit-impact execution manifests are still required for impact closure",
        ],
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--input-json", type=Path)
    parser.add_argument("--semantic-graph", type=Path)
    parser.add_argument("--project-source-readiness", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--worker-ledger-json", type=Path)
    parser.add_argument("--worker-ledger-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    input_path = (args.input_json or workspace / DEFAULT_INPUT).expanduser().resolve()
    semantic_graph_path = (args.semantic_graph or workspace / DEFAULT_SEMANTIC_GRAPH).expanduser().resolve()
    project_source_readiness_path = (
        args.project_source_readiness.expanduser().resolve()
        if args.project_source_readiness
        else (workspace / DEFAULT_PROJECT_SOURCE_READINESS).expanduser().resolve()
    )
    bundle_dir = (args.bundle_dir or workspace / DEFAULT_BUNDLE_DIR).expanduser().resolve()
    payload = build_payload(
        workspace,
        input_path=input_path,
        semantic_graph_path=semantic_graph_path,
        project_source_readiness_path=project_source_readiness_path,
        bundle_dir=bundle_dir,
    )

    out_json = (args.out_json or workspace / DEFAULT_OUT).expanduser().resolve()
    out_md = (args.out_md or workspace / DEFAULT_OUT_MD).expanduser().resolve()
    write_json(out_json, payload)
    write_text(out_md, render_markdown(payload))

    ledger = worker_ledger(payload)
    ledger_json = (args.worker_ledger_json or workspace / WORKER_LEDGER_JSON).expanduser().resolve()
    ledger_md = (args.worker_ledger_md or workspace / WORKER_LEDGER_MD).expanduser().resolve()
    write_json(ledger_json, ledger)
    write_text(ledger_md, render_markdown({**payload, "reductions": payload["reductions"][:30]}))

    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[impact-binding-discovery] OK "
        f"reduced={payload['reduced_unit_count']} terminal={payload['terminal_reduced_unit_count']} "
        f"source_roots={payload['project_source_root_count']} hints={payload['candidate_source_hint_unit_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
