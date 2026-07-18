#!/usr/bin/env python3
"""Build a Rust/DLT runtime-semantic blocker and handoff queue.

This PR560 bridge consumes the stdlib Rust source graph, cross-crate import
graph, and scan-rust semantic accounting. It does not resolve runtime calls or
prove findings. Its job is to turn the remaining Rust/DLT semantic gaps into a
bounded, concrete queue for Base/Rust workspaces: either a blocker row that
needs runtime/source proof, or a safe detectorization handoff row when the
source shape is narrow enough for fixture-first detector work.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUST_SOURCE_GRAPH = ROOT / "tools" / "rust-source-graph.py"
RUST_CROSS_CRATE_GRAPH = ROOT / "tools" / "rust-cross-crate-graph.py"
SCHEMA = "auditooor.rust_runtime_semantic_blockers.v1"
LIMITATIONS = [
    "Rust/DLT rows are source-shape and import-graph planning evidence only",
    "the queue records macro/cfg/trait-method hints but does not expand macros, type-check traits, select cfg feature sets, or prove runtime call targets",
    "cross-crate edges are import/dependency edges, not concrete invocation proof",
    "scanner signals from cargo audit, Semgrep, and Clippy do not prove runtime semantic coverage",
    "detectorization handoff rows still require vulnerable fixture, clean fixture, smoke output, and exact impact proof",
    "all rows remain NOT_SUBMIT_READY with severity none until production-path and execution proof exist",
]

RUNTIME_COMPONENT_FAMILIES: dict[str, dict[str, Any]] = {
    "consensus_client": {
        "tokens": ("consensus", "fork", "finality", "validator", "attestation", "beacon"),
        "state_machine": "fork-choice/finality/validator-state transition model",
        "trust_boundaries": ("peer input", "engine API payload", "validator duty", "fork schedule"),
        "proof_artifacts": ("same-input divergence model", "fork-choice replay", "state-root assertion"),
    },
    "execution_client": {
        "tokens": ("reth", "evm", "execute", "transaction", "block", "state root", "engine"),
        "state_machine": "block execution / transaction application / state-root transition model",
        "trust_boundaries": ("RPC input", "engine API", "database/cache", "block body"),
        "proof_artifacts": ("execution trace fixture", "differential state-root replay", "resource benchmark"),
    },
    "tee_runtime": {
        "tokens": ("tee", "enclave", "attestation", "quote", "measurement", "secure"),
        "state_machine": "attestation lifecycle / enclave measurement / key-release model",
        "trust_boundaries": ("attestation verifier", "quote parser", "enclave key material", "host input"),
        "proof_artifacts": ("production attestation path", "negative quote fixture", "trust-boundary matrix"),
    },
    "zk_runtime": {
        "tokens": ("zk", "proof", "verifier", "circuit", "constraint", "stark", "snark"),
        "state_machine": "proof generation/verifier binding/runtime assumption model",
        "trust_boundaries": ("proof bytes", "public inputs", "verifier key", "mock-vs-production verifier"),
        "proof_artifacts": ("production verifier path", "negative proof fixture", "public-input binding assertion"),
    },
    "runtime_resource": {
        "tokens": ("decode", "allocation", "memory", "cpu", "resource", "unsafe", "cache"),
        "state_machine": "bounded input/resource lifecycle model",
        "trust_boundaries": ("untrusted bytes", "allocator", "cache", "parser boundary"),
        "proof_artifacts": ("bounded input fixture", "resource benchmark", "threshold mapping"),
    },
}

WORKSPACE_NEUTRALITY_REQUIREMENTS = [
    "command accepts --workspace/WS and writes under that workspace",
    "artifact is advisory and workspace-local",
    "row cannot close from a Base-only wrapper; require a hermetic or non-Base fixture/check before closure",
    "runtime proof must bind an entrypoint/event source, actor input, state precondition, impact assertion, and replay command",
]


def _load_json(path: Path, label: str, *, required: bool = False) -> dict[str, Any]:
    if not path.is_file():
        if required:
            raise SystemExit(f"[rust-runtime-semantic-blockers] missing {label}: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[rust-runtime-semantic-blockers] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[rust-runtime-semantic-blockers] expected object JSON for {label}: {path}")
    return payload


def _run_graph(tool: Path, workspace: Path) -> None:
    subprocess.run(
        [sys.executable, str(tool), "--workspace", str(workspace)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _ensure_artifacts(workspace: Path, source_path: Path, cross_path: Path, *, generate: bool) -> None:
    if not generate:
        return
    if not source_path.is_file():
        _run_graph(RUST_SOURCE_GRAPH, workspace)
    if not cross_path.is_file():
        _run_graph(RUST_CROSS_CRATE_GRAPH, workspace)


def _slug(value: str, fallback: str = "rust-runtime") -> str:
    out = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return out or fallback


def _runtime_family(title: str, details: list[str], blocker_ids: list[str]) -> str:
    blob = " ".join([title, *details, *blocker_ids]).lower().replace("-", " ")
    scores: dict[str, int] = {}
    for family, spec in RUNTIME_COMPONENT_FAMILIES.items():
        scores[family] = sum(1 for token in spec["tokens"] if token in blob)
    family, score = max(scores.items(), key=lambda item: (item[1], item[0]))
    if score:
        return family
    if "trait" in blob or "call resolution" in blob or "cross crate" in blob:
        return "execution_client"
    return "runtime_resource"


def _crate_rows(source_graph: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    rows: list[tuple[str, dict[str, Any]]] = []
    for crate, payload in source_graph.items():
        if crate == "_meta" or not isinstance(payload, dict):
            continue
        rows.append((str(crate), payload))
    return sorted(rows, key=lambda item: item[0])


def _cross_crate_edges(cross_graph: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in (cross_graph.get("edges") or []) if isinstance(row, dict)]


def _depth_items(scan_summary: dict[str, Any]) -> list[dict[str, Any]]:
    accounting = scan_summary.get("semantic_depth_accounting")
    if not isinstance(accounting, dict):
        return []
    return [row for row in (accounting.get("items") or []) if isinstance(row, dict)]


def _scanner_status(scan_summary: dict[str, Any]) -> dict[str, Any]:
    sem = scan_summary.get("semantic_inventory") if isinstance(scan_summary.get("semantic_inventory"), dict) else {}
    source = sem.get("source_graph") if isinstance(sem.get("source_graph"), dict) else {}
    cross = sem.get("cross_crate_graph") if isinstance(sem.get("cross_crate_graph"), dict) else {}
    return {
        "scan_summary_present": bool(scan_summary),
        "semantic_inventory_status": sem.get("status", ""),
        "source_graph_status": source.get("status", ""),
        "cross_crate_graph_status": cross.get("status", ""),
        "source_graph_blocker": source.get("blocker", ""),
        "cross_crate_graph_blocker": cross.get("blocker", ""),
    }


def _base_row(
    *,
    idx: int,
    source_kind: str,
    source_id: str,
    crate: str = "",
    file: str = "",
    line: int = 0,
    title: str,
    blocker_ids: list[str],
    action_lane: str,
    detector_family: str = "",
    details: list[str] | None = None,
    next_command: str,
) -> dict[str, Any]:
    status = "detectorization_handoff" if action_lane == "safe_detectorization_handoff" else "runtime_semantic_blocked"
    fixture_slug = _slug(detector_family or title).replace("-", "_")
    details = details or []
    runtime_family = _runtime_family(title, details, blocker_ids)
    runtime_spec = RUNTIME_COMPONENT_FAMILIES[runtime_family]
    row: dict[str, Any] = {
        "queue_id": f"RRS-{idx:03d}",
        "source_kind": source_kind,
        "source_id": source_id,
        "crate": crate,
        "file": file,
        "line": line,
        "title": title,
        "status": status,
        "action_lane": action_lane,
        "blocker_ids": sorted(set(blocker_ids)),
        "details": details,
        "runtime_component_family": runtime_family,
        "runtime_model_requirement": {
            "state_machine": runtime_spec["state_machine"],
            "trust_boundaries": list(runtime_spec["trust_boundaries"]),
            "required_proof_artifacts": list(runtime_spec["proof_artifacts"]),
            "model_status": "required_not_collected",
        },
        "harness_binding_requirement": {
            "status": "blocked_missing_runtime_binding",
            "required_inputs": [
                "entrypoint or runtime event source",
                "actor/peer/RPC/prover input shape",
                "state precondition and fork/config assumptions",
                "observable impact assertion",
                "replay or integration command",
            ],
            "record_command_template": "make poc-execution-record WS=<workspace> BRIEF=<brief> CMD='<executed runtime/harness command>' RESULT=needs_human IMPACT=unknown",
        },
        "workspace_neutrality_requirement": {
            "status": "required_not_demonstrated",
            "requirements": WORKSPACE_NEUTRALITY_REQUIREMENTS,
            "non_base_or_hermetic_check": "required_before_closure",
        },
        "executable_next_commands": [
            next_command,
            "python3 tools/impact-miss-offset-benchmark.py --workspace <workspace> --emit-harness-blockers --derive-predictions",
            "make poc-execution-record WS=<workspace> BRIEF=<brief> CMD='<executed runtime/harness command>' RESULT=needs_human IMPACT=unknown",
        ],
        "next_command": next_command,
        "coverage_claim": "none_source_shape_only",
        "advisory_only": True,
        "promotion_allowed": False,
        "semantic_completeness_claim": False,
        "severity": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "impact_contract_required": True,
        "source_shape_limitations": LIMITATIONS,
    }
    if detector_family:
        row["detectorization_handoff"] = {
            "candidate_detector_family": detector_family,
            "required_artifacts": [
                "detector predicate diff",
                "vulnerable Rust/DLT fixture",
                "clean Rust/DLT fixture",
                "smoke output with positive>=1 and clean==0",
                "exact impact contract before harness/report work",
            ],
            "fixture_paths": {
                "positive": f"detectors/fixtures/{fixture_slug}/{row['queue_id'].lower()}_positive.rs",
                "clean": f"detectors/fixtures/{fixture_slug}/{row['queue_id'].lower()}_clean.rs",
                "smoke": f"detectors/fixtures/{fixture_slug}/{row['queue_id'].lower()}_smoke.json",
            },
        }
    return row


def _runtime_readiness_gates(runtime_family_counts: dict[str, int]) -> list[dict[str, Any]]:
    gates: list[dict[str, Any]] = []
    for family, spec in sorted(RUNTIME_COMPONENT_FAMILIES.items()):
        matching = int(runtime_family_counts.get(family, 0))
        gates.append(
            {
                "runtime_component_family": family,
                "matching_queue_rows": matching,
                "status": "observed_but_unproved" if matching else "missing_workspace_evidence",
                "required_before_closure": [
                    "family-specific source row or explicit not-applicable rationale",
                    "runtime model with state machine and trust-boundary inputs",
                    "project-bound or hermetic executable harness/replay command",
                    "poc_execution manifest with final_result=proved only after real impact assertion",
                    "non-Base/hermetic demonstration for workspace-neutral closure",
                ],
                "state_machine": spec["state_machine"],
                "trust_boundaries": list(spec["trust_boundaries"]),
                "required_proof_artifacts": list(spec["proof_artifacts"]),
                "closure_boundary": "not closed by this queue; closes only through executed proof or explicit terminal missing-evidence blocker",
            }
        )
    return gates


def _entrypoint_rows(idx: int, crate: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    external_count = len(payload.get("external_calls") or [])
    value_count = len(payload.get("value_movement_calls") or [])
    unsafe_count = len(payload.get("unsafe_blocks") or [])
    for entry in payload.get("entrypoints") or []:
        if not isinstance(entry, dict):
            continue
        fn = str(entry.get("fn") or "")
        blockers = ["rust-runtime-call-resolution", "rust-state-write-model"]
        details = [
            f"crate has {external_count} external-call tokens, {value_count} value-movement tokens, and {unsafe_count} unsafe blocks",
            "entrypoint needs runtime receiver/account/asset resolution before impact work",
        ]
        lane = "runtime_semantic_blocker_queue"
        detector_family = ""
        if external_count and value_count:
            lane = "safe_detectorization_handoff"
            detector_family = "rust_external_call_value_movement"
            blockers.append("rust-fixture-smoke-required")
            details.append("narrow source shape can seed fixture-first detectorization but is not proof")
        rows.append(_base_row(
            idx=idx + len(rows),
            source_kind="rust_source_graph.entrypoint",
            source_id=f"{crate}.{fn}",
            crate=crate,
            file=str(entry.get("file") or ""),
            line=int(entry.get("line") or 0),
            title=f"Resolve runtime semantics for Rust entrypoint {crate}.{fn}",
            blocker_ids=blockers,
            action_lane=lane,
            detector_family=detector_family,
            details=details,
            next_command="make rust-runtime-semantic-blockers WS=<workspace> GENERATE=1",
        ))
    return rows


def _shape_rows(idx: int, crate: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    shape_specs = [
        ("external_calls", "rust_source_graph.external_call", "rust-runtime-call-resolution", "Resolve concrete runtime receiver for Rust external call", "rust_external_call_receiver"),
        ("value_movement_calls", "rust_source_graph.value_movement", "rust-value-flow-model", "Resolve asset/account/amount semantics for Rust value movement", "rust_value_movement_flow"),
        ("unsafe_blocks", "rust_source_graph.unsafe_block", "rust-unsafe-reachability", "Tie unsafe block to external caller and exploit precondition", "rust_unsafe_reachability"),
        ("trait_impls", "rust_source_graph.trait_impl", "rust-trait-dispatch", "Resolve trait dispatch target and caller role", ""),
        ("trait_method_impls", "rust_source_graph.trait_method_impl", "rust-trait-method-dispatch", "Bind trait method implementation to concrete runtime caller", ""),
        ("cfg_attrs", "rust_source_graph.cfg_attr", "rust-cfg-feature-resolution", "Resolve cfg/feature-gated runtime branch", ""),
        ("macro_invocations", "rust_source_graph.macro_invocation", "rust-macro-expansion-required", "Resolve macro-expanded runtime call/account shape", ""),
    ]
    for key, source_kind, blocker, title, detector_family in shape_specs:
        for row in payload.get(key) or []:
            if not isinstance(row, dict):
                continue
            source_id = f"{crate}:{key}:{row.get('file', '')}:{row.get('line', 0)}"
            name = (
                row.get("call")
                or row.get("method")
                or row.get("macro")
                or row.get("feature")
                or row.get("trait")
                or key
            )
            lane = "safe_detectorization_handoff" if detector_family and key != "trait_impls" else "runtime_semantic_blocker_queue"
            detail = (
                row.get("snippet")
                or row.get("struct")
                or row.get("expr")
                or row.get("macro")
                or row.get("method")
                or ""
            )
            rows.append(_base_row(
                idx=idx + len(rows),
                source_kind=source_kind,
                source_id=source_id,
                crate=crate,
                file=str(row.get("file") or ""),
                line=int(row.get("line") or 0),
                title=f"{title}: {crate}.{name}",
                blocker_ids=[blocker, "rust-production-path-proof-required"],
                action_lane=lane,
                detector_family=detector_family if lane == "safe_detectorization_handoff" else "",
                details=[str(detail)],
                next_command="make rust-runtime-semantic-blockers WS=<workspace> GENERATE=1",
            ))
    return rows


def _edge_rows(idx: int, cross_graph: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for edge in _cross_crate_edges(cross_graph):
        from_crate = str(edge.get("from_crate") or "")
        to_crate = str(edge.get("to_crate") or "")
        rows.append(_base_row(
            idx=idx + len(rows),
            source_kind="rust_cross_crate_graph.edge",
            source_id=f"{from_crate}->{to_crate}:{edge.get('from_file', '')}",
            crate=from_crate,
            file=str(edge.get("from_file") or ""),
            line=0,
            title=f"Resolve runtime invocation for Rust cross-crate edge {from_crate}->{to_crate}",
            blocker_ids=["rust-cross-crate-import-not-invocation", "rust-runtime-call-resolution"],
            action_lane="runtime_semantic_blocker_queue",
            details=[f"to_path={edge.get('to_path', '')}"],
            next_command="python3 tools/rust-cross-crate-graph.py --workspace <workspace> --validate",
        ))
    return rows


def _depth_rows(idx: int, scan_summary: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in _depth_items(scan_summary):
        status = str(item.get("status") or "")
        if status == "implemented":
            continue
        item_id = str(item.get("id") or "")
        rows.append(_base_row(
            idx=idx + len(rows),
            source_kind="scan_rust.semantic_depth_accounting",
            source_id=item_id,
            title=f"Close scan-rust semantic depth item {item_id}: {item.get('area', '')}",
            blocker_ids=[f"scan-rust-{_slug(str(item.get('area') or 'semantic-depth'))}"],
            action_lane="runtime_semantic_blocker_queue",
            details=[str(item.get("detail") or "")],
            next_command="tools/rust-scan-runner.sh <workspace>",
        ))
    return rows


def build_payload(
    workspace: Path,
    source_graph: dict[str, Any],
    cross_graph: dict[str, Any],
    scan_summary: dict[str, Any],
    *,
    limit: int,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for crate, payload in _crate_rows(source_graph):
        if len(rows) >= limit:
            break
        rows.extend(_entrypoint_rows(len(rows) + 1, crate, payload))
        if len(rows) >= limit:
            rows = rows[:limit]
            break
        rows.extend(_shape_rows(len(rows) + 1, crate, payload))
        rows = rows[:limit]
    if len(rows) < limit:
        rows.extend(_edge_rows(len(rows) + 1, cross_graph))
        rows = rows[:limit]
    if len(rows) < limit:
        rows.extend(_depth_rows(len(rows) + 1, scan_summary))
        rows = rows[:limit]

    status_counts: dict[str, int] = {}
    lane_counts: dict[str, int] = {}
    blocker_counts: dict[str, int] = {}
    runtime_family_counts: dict[str, int] = {}
    for row in rows:
        status_counts[str(row.get("status") or "unknown")] = status_counts.get(str(row.get("status") or "unknown"), 0) + 1
        lane_counts[str(row.get("action_lane") or "unknown")] = lane_counts.get(str(row.get("action_lane") or "unknown"), 0) + 1
        runtime_family_counts[str(row.get("runtime_component_family") or "unknown")] = (
            runtime_family_counts.get(str(row.get("runtime_component_family") or "unknown"), 0) + 1
        )
        for blocker in row.get("blocker_ids") or []:
            blocker_counts[str(blocker)] = blocker_counts.get(str(blocker), 0) + 1

    source_crates = _crate_rows(source_graph)
    possible_count = (
        sum(
            len(payload.get("entrypoints") or [])
            + len(payload.get("external_calls") or [])
            + len(payload.get("value_movement_calls") or [])
            + len(payload.get("unsafe_blocks") or [])
            + len(payload.get("trait_impls") or [])
            + len(payload.get("trait_method_impls") or [])
            + len(payload.get("cfg_attrs") or [])
            + len(payload.get("macro_invocations") or [])
            for _, payload in source_crates
        )
        + len(_cross_crate_edges(cross_graph))
        + len([item for item in _depth_items(scan_summary) if str(item.get("status") or "") != "implemented"])
    )
    runtime_readiness_gates = _runtime_readiness_gates(runtime_family_counts)
    readiness_status_counts: dict[str, int] = {}
    for gate in runtime_readiness_gates:
        status = str(gate.get("status") or "unknown")
        readiness_status_counts[status] = readiness_status_counts.get(status, 0) + 1

    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "limit": limit,
        "item_count": len(rows),
        "truncated": possible_count > len(rows),
        "possible_source_shape_item_count": possible_count,
        "coverage_claim": "none_source_shape_only",
        "advisory_only": True,
        "promotion_allowed": False,
        "semantic_completeness_claim": False,
        "severity": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "impact_contract_required": True,
        "source_shape_limitations": LIMITATIONS,
        "source_artifacts": {
            "rust_source_graph": str(workspace / ".auditooor" / "rust_source_graph.json"),
            "rust_cross_crate_graph": str(workspace / ".auditooor" / "rust_cross_crate_graph.json"),
            "scan_rust_summary": str(workspace / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json"),
        },
        "scanner_status": _scanner_status(scan_summary),
        "summary": {
            "crate_count": len(source_crates),
            "cross_crate_edge_count": len(_cross_crate_edges(cross_graph)),
            "scan_rust_depth_item_count": len(_depth_items(scan_summary)),
            "trait_impl_count": sum(len(payload.get("trait_impls") or []) for _, payload in source_crates),
            "trait_method_impl_count": sum(len(payload.get("trait_method_impls") or []) for _, payload in source_crates),
            "cfg_attr_count": sum(len(payload.get("cfg_attrs") or []) for _, payload in source_crates),
            "macro_invocation_count": sum(len(payload.get("macro_invocations") or []) for _, payload in source_crates),
        },
        "semantic_resolution_hint_summary": {
            "trait_method_impls_indexed": sum(len(payload.get("trait_method_impls") or []) for _, payload in source_crates),
            "cfg_attrs_indexed": sum(len(payload.get("cfg_attrs") or []) for _, payload in source_crates),
            "macro_invocations_indexed": sum(len(payload.get("macro_invocations") or []) for _, payload in source_crates),
            "status": "hints_indexed_unproved",
            "closure_boundary": "Trait/cfg/macro hints reduce reviewer search space but still require cargo/rustc or runtime proof before closure.",
        },
        "status_counts": status_counts,
        "action_lane_counts": lane_counts,
        "blocker_counts": blocker_counts,
        "runtime_component_family_counts": runtime_family_counts,
        "runtime_model_matrix": [
            {
                "runtime_component_family": family,
                "state_machine": spec["state_machine"],
                "trust_boundaries": list(spec["trust_boundaries"]),
                "required_proof_artifacts": list(spec["proof_artifacts"]),
                "matching_queue_rows": runtime_family_counts.get(family, 0),
                "status": "covered_by_queue_rows" if runtime_family_counts.get(family, 0) else "not_observed_in_source_shape",
                "closure_boundary": "not closed until an executed runtime/integration proof or exact missing-evidence blocker is recorded",
            }
            for family, spec in sorted(RUNTIME_COMPONENT_FAMILIES.items())
        ],
        "runtime_readiness_gates": runtime_readiness_gates,
        "runtime_readiness_summary": {
            "status_counts": readiness_status_counts,
            "workspace_neutrality_requirements": WORKSPACE_NEUTRALITY_REQUIREMENTS,
            "closure_boundary": "Rows reduce runtime/Impact-Miss gaps but do not close proof without executable runtime evidence.",
        },
        "items": rows,
        "next_actions": [
            "Run rust-source-graph and rust-cross-crate-graph before treating Base/Rust workspaces as inventoried.",
            "Use safe_detectorization_handoff rows only for fixture-first detector work; do not promote without smoke output.",
            "Use runtime_semantic_blocker_queue rows for source review, runtime call resolution, cfg/trait/macro adjudication, or explicit kill notes.",
            "Keep all Rust/DLT rows out of submission language until exact impact, production path, and execution proof exist.",
            "For each runtime_component_family row, bind the named state machine to an executable integration/replay command or record the exact missing runtime evidence.",
            "For each runtime_readiness_gates row, either collect a family-specific project/hermetic proof or record why that runtime family is out of scope for the workspace.",
        ],
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Rust/DLT Runtime Semantic Blockers",
        "",
        "Bounded queue for Rust/Base runtime-semantic blockers and safe detectorization handoffs.",
        "Rows are advisory only; this artifact makes no semantic completeness claim.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- item count: {payload['item_count']}",
        f"- possible source-shape items: {payload['possible_source_shape_item_count']}",
        f"- truncated: `{str(payload['truncated']).lower()}`",
        f"- submission posture: `{payload['submission_posture']}`",
        f"- semantic completeness claim: `{str(payload['semantic_completeness_claim']).lower()}`",
        "",
        "## Limitations",
        "",
    ]
    for limitation in payload.get("source_shape_limitations", []):
        lines.append(f"- {limitation}")
    lines.extend(["", "## Counts", ""])
    for key, count in sorted((payload.get("action_lane_counts") or {}).items()):
        lines.append(f"- `{key}`: {count}")
    lines.extend(["", "## Runtime Model Matrix", ""])
    lines.extend([
        "| Family | Matching rows | State machine | Required proof artifacts |",
        "|---|---:|---|---|",
    ])
    for row in payload.get("runtime_model_matrix", []):
        lines.append("| `{}` | {} | {} | {} |".format(
            row.get("runtime_component_family", ""),
            row.get("matching_queue_rows", 0),
            row.get("state_machine", ""),
            ", ".join(row.get("required_proof_artifacts") or []),
        ))
    lines.extend(["", "## Runtime Readiness Gates", ""])
    lines.extend([
        "| Family | Status | Matching rows | Required before closure |",
        "|---|---|---:|---|",
    ])
    for row in payload.get("runtime_readiness_gates", []):
        lines.append("| `{}` | `{}` | {} | {} |".format(
            row.get("runtime_component_family", ""),
            row.get("status", ""),
            row.get("matching_queue_rows", 0),
            "; ".join(row.get("required_before_closure") or []),
        ))
    lines.extend(["", "## Queue", ""])
    if not payload.get("items"):
        lines.append("_No Rust/DLT runtime semantic queue rows were generated._")
    else:
        lines.extend([
            "| ID | Lane | Status | Crate | Source | Blockers | Next command |",
            "|---|---|---|---|---|---|---|",
        ])
        for row in payload.get("items", []):
            lines.append("| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                row.get("queue_id", ""),
                row.get("action_lane", ""),
                row.get("status", ""),
                row.get("crate", ""),
                row.get("source_id", ""),
                ",".join(row.get("blocker_ids") or []),
                row.get("next_command", ""),
            ))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--source-graph", type=Path)
    parser.add_argument("--cross-crate-graph", type=Path)
    parser.add_argument("--scan-summary", type=Path)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--generate-graphs", action="store_true")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[rust-runtime-semantic-blockers] workspace not found: {workspace}", file=sys.stderr)
        return 2
    audit_dir = workspace / ".auditooor"
    source_path = (args.source_graph or audit_dir / "rust_source_graph.json").expanduser().resolve()
    cross_path = (args.cross_crate_graph or audit_dir / "rust_cross_crate_graph.json").expanduser().resolve()
    scan_path = (args.scan_summary or workspace / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json").expanduser().resolve()
    try:
        _ensure_artifacts(workspace, source_path, cross_path, generate=args.generate_graphs)
    except subprocess.CalledProcessError as exc:
        print(f"[rust-runtime-semantic-blockers] graph generation failed: {exc}", file=sys.stderr)
        return 2

    source_graph = _load_json(source_path, "rust source graph")
    cross_graph = _load_json(cross_path, "rust cross-crate graph")
    scan_summary = _load_json(scan_path, "scan-rust summary")
    payload = build_payload(
        workspace,
        source_graph,
        cross_graph,
        scan_summary,
        limit=max(0, args.limit),
    )
    out_json = args.out_json or audit_dir / "rust_runtime_semantic_blockers.json"
    out_md = args.out_md or audit_dir / "rust_runtime_semantic_blockers.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[rust-runtime-semantic-blockers] OK items={payload['item_count']} json={out_json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
