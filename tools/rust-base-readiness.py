#!/usr/bin/env python3
"""Report Rust corpus and Base/Blockchain-DLT scan readiness.

This is a no-network readiness gate. It answers whether local Rust/ZK bug
corpora have actually been ingested, whether Rust semantic scan artifacts are
present, and what exact local inputs are still needed before a fresh Base scan
can safely move beyond blocker accounting.
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from pathlib import Path
from typing import Any, Sequence


SCHEMA = "auditooor.rust_base_scan_readiness.v1"
DEFAULT_OUT = ".auditooor/rust_base_scan_readiness.json"
DEFAULT_OUT_MD = ".auditooor/rust_base_scan_readiness.md"
SOURCE_SUFFIXES = (".sol", ".rs", ".cairo", ".move", ".vy")
RUST_ROOT_MARKERS = ("Cargo.toml",)
SMART_ROOT_MARKERS = ("foundry.toml", "hardhat.config.js", "hardhat.config.ts", "truffle-config.js")
PLACEHOLDER_MARKERS = (
    "todo",
    "placeholder",
    "paste",
    "copy from bounty",
    "rubric unavailable",
    "scope unavailable",
)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[rust-base-readiness] invalid JSON at {path}: {exc}") from None


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def _count_files(root: Path, patterns: Sequence[str]) -> int:
    if not root.is_dir():
        return 0
    total = 0
    for pattern in patterns:
        total += sum(1 for path in root.rglob(pattern) if path.is_file())
    return total


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _looks_populated(path: Path) -> bool:
    text = _read_text(path)
    if not text.strip():
        return False
    lowered = text.lower()
    return not any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def _resolve_optional_roots(roots: Sequence[Path] | None) -> list[Path]:
    return [root.expanduser().resolve() for root in roots or []]


def _root_status(root: Path) -> dict[str, Any]:
    exists = root.exists()
    is_dir = root.is_dir()
    solidity = _count_files(root, ["*.sol"]) if is_dir else 0
    rust = _count_files(root, ["*.rs"]) if is_dir else 0
    cargo = _count_files(root, ["Cargo.toml"]) if is_dir else 0
    cairo = _count_files(root, ["*.cairo"]) if is_dir else 0
    move = _count_files(root, ["*.move"]) if is_dir else 0
    marker_hits = [name for name in (*RUST_ROOT_MARKERS, *SMART_ROOT_MARKERS) if (root / name).exists()] if is_dir else []
    return {
        "path": str(root),
        "exists": exists,
        "is_dir": is_dir,
        "solidity_files": solidity,
        "rust_files": rust,
        "cargo_manifests": cargo,
        "cairo_files": cairo,
        "move_files": move,
        "marker_hits": marker_hits,
        "has_smart_contract_source": bool(solidity or any(name in marker_hits for name in SMART_ROOT_MARKERS)),
        "has_rust_source": bool(rust or cargo),
    }


def _declared_language_count(root: dict[str, Any], language: str, suffix: str) -> int:
    presence = root.get("language_presence")
    if isinstance(presence, dict):
        return int(presence.get(language) or 0)
    suffix_counts = root.get("suffix_counts")
    if isinstance(suffix_counts, dict):
        return int(suffix_counts.get(suffix) or 0)
    return sum(
        1
        for item in root.get("sample_files", [])
        if isinstance(item, dict) and str(item.get("suffix")) == suffix
    )


def _declared_labels_for_language(declared_roots: list[dict[str, Any]], language: str, suffix: str) -> list[str]:
    labels: list[str] = []
    for root in declared_roots:
        expected = {str(item).lower() for item in root.get("expected_languages", [])}
        count = _declared_language_count(root, language, suffix)
        if count or language in expected:
            labels.append(str(root.get("label") or root.get("workspace_relative_path") or root.get("declared_path") or "unnamed"))
    return labels


def _first_existing(paths: Sequence[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None


def zkbugs_status(workspace: Path, zkbugs_root: Path | None) -> dict[str, Any]:
    index_path = workspace / ".audit_logs" / "zkbugs_farming" / "zkbugs_index.json"
    queue_path = workspace / ".audit_logs" / "zkbugs_farming" / "provider_queue" / "zkbugs_provider_queue.json"
    readiness_path = workspace / ".audit_logs" / "zkbugs_farming" / "zkbugs_readiness.json"
    task_map_path = workspace / ".audit_logs" / "zkbugs_farming" / "zkbugs_task_map.json"
    route_completeness_path = workspace / ".audit_logs" / "zkbugs_farming" / "task_queues" / "zkbugs_route_completeness.json"
    last_pull_path = workspace / ".auditooor" / "zkbugs_last_pull"
    index = load_json(index_path)
    queue = load_json(queue_path)
    readiness = load_json(readiness_path)
    task_map = load_json(task_map_path)
    route_completeness = load_json(route_completeness_path)
    root = zkbugs_root.expanduser().resolve() if zkbugs_root else None
    root_looks_valid = bool(root and (root / "dataset").is_dir())
    total = int(((index.get("summary") or {}).get("total") or 0) if isinstance(index, dict) else 0)
    brief_count = len(index.get("briefs") or []) if isinstance(index, dict) else 0
    queue_rows = len(queue.get("rows") or queue.get("items") or []) if isinstance(queue, dict) else 0
    readiness_counts = readiness.get("counts") if isinstance(readiness, dict) else {}
    repo_content_ready = (
        bool(readiness.get("status") == "ready")
        if readiness_path.is_file() and isinstance(readiness, dict)
        else bool(total and queue_rows)
    )
    readiness_blockers = readiness.get("blockers") if isinstance(readiness, dict) and isinstance(readiness.get("blockers"), list) else []
    status = "ingested" if total else "not_ingested"
    if total and not queue_rows:
        status = "ingested_no_provider_queue"
    if repo_content_ready:
        status = "repo_content_indexed_and_queued"
    route_status = str(route_completeness.get("status") or "missing") if isinstance(route_completeness, dict) else "missing"
    return {
        "status": status,
        "fully_mined": repo_content_ready,
        "repo_content_indexed_and_queued": repo_content_ready,
        "task_map_path": str(task_map_path),
        "task_map_present": task_map_path.is_file(),
        "route_completeness_path": str(route_completeness_path),
        "route_completeness_present": route_completeness_path.is_file(),
        "route_completeness_status": route_status,
        "route_covered_tasks": len(route_completeness.get("covered_task_ids") or []) if isinstance(route_completeness, dict) else 0,
        "route_uncovered_tasks": len(route_completeness.get("uncovered_task_ids") or []) if isinstance(route_completeness, dict) else 0,
        "detector_queue_rows": int(route_completeness.get("detector_queue_rows") or 0) if isinstance(route_completeness, dict) else 0,
        "invariant_queue_rows": int(route_completeness.get("invariant_queue_rows") or 0) if isinstance(route_completeness, dict) else 0,
        "replay_queue_rows": int(route_completeness.get("replay_queue_rows") or 0) if isinstance(route_completeness, dict) else 0,
        "provider_prompt_queue_rows": int(route_completeness.get("provider_prompt_queue_rows") or queue_rows) if isinstance(route_completeness, dict) else queue_rows,
        "task_map_total": int((task_map.get("summary") or {}).get("total_tasks") or 0) if isinstance(task_map, dict) else 0,
        "readiness_path": str(readiness_path),
        "readiness_present": readiness_path.is_file(),
        "readiness_blockers": readiness_blockers,
        "index_path": str(index_path),
        "index_present": index_path.is_file(),
        "last_pull_path": str(last_pull_path),
        "last_pull_present": last_pull_path.is_file(),
        "provider_pull_recorded": last_pull_path.is_file(),
        "total_records": total,
        "repo_content_records": int(readiness_counts.get("repo_content_records") or total) if isinstance(readiness_counts, dict) else total,
        "brief_count": brief_count,
        "provider_queue_rows": queue_rows,
        "provided_root": str(root) if root else "",
        "provided_root_valid": root_looks_valid,
        "next_commands": [
            "make extract DIR=<local_zksecurity_zkbugs_checkout>/reports/documents",
            "make zkbugs-ingest ZKBUGS_ROOT=<local_zksecurity_zkbugs_checkout> BRIEF_LIMIT=0 INDEX_LIMIT=0",
            "make zkbugs-brief-queue BRIEF_DIR=.audit_logs/zkbugs_farming/briefs LIMIT=0",
            "make zkbugs-task-map JSON=1",
            "python3 tools/zkbugs-readiness.py --zkbugs-root <local_zksecurity_zkbugs_checkout> --strict",
        ],
        "proof_boundary": "zkBugs readiness is based on local repo-content configs/code/report artifacts, not GitHub issue titles. Provider pulls are separate; promotion still requires detector smoke or replayable counterexample plus Codex review.",
    }


def rustbugs_status(workspace: Path, rustbugs_root: Path | None) -> dict[str, Any]:
    tool_candidates = [workspace / "tools" / "rustbugs-ingest.py", workspace / "tools" / "rustbugs-brief-queue.py"]
    existing_tool = _first_existing(tool_candidates)
    root = rustbugs_root.expanduser().resolve() if rustbugs_root else None
    root_rs_files = _count_files(root, ["*.rs"]) if root else 0
    root_manifest_files = _count_files(root, ["Cargo.toml", "*.json", "*.md"]) if root else 0
    artifact_candidates = [
        workspace / ".audit_logs" / "rustbugs_farming" / "rustbugs_index.json",
        workspace / ".audit_logs" / "rustbugs" / "rustbugs_index.json",
        workspace / ".auditooor" / "rustbugs_index.json",
    ]
    artifact = _first_existing(artifact_candidates)
    index = load_json(artifact) if artifact else {}
    records = index.get("records") if isinstance(index, dict) else []
    status = "unsupported_no_ingestor"
    if existing_tool:
        status = "ingestor_present_not_run" if not artifact else "ingested"
    elif root and root.exists():
        status = "local_root_present_no_ingestor"
    return {
        "status": status,
        "fully_mined": bool(existing_tool and artifact and records),
        "ingestor_present": bool(existing_tool),
        "ingestor_path": str(existing_tool) if existing_tool else "",
        "index_path": str(artifact) if artifact else "",
        "index_present": bool(artifact),
        "record_count": len(records) if isinstance(records, list) else 0,
        "provided_root": str(root) if root else "",
        "provided_root_exists": bool(root and root.exists()),
        "provided_root_rs_files": root_rs_files,
        "provided_root_manifest_files": root_manifest_files,
        "next_commands": [
            "add tools/rustbugs-ingest.py or map RustBugs into the existing zkbugs/corpus farming schema",
            "python3 tools/rustbugs-ingest.py --rustbugs-root <local_rustbugs_checkout> --out-dir .audit_logs/rustbugs_farming",
            "build vulnerable/clean Rust fixtures or replayable counterexamples before detector promotion",
        ],
        "proof_boundary": "No RustBugs-specific corpus is fully mined until a local corpus index, briefs, and smoke/replay promotion artifacts exist.",
    }


def rust_scan_status(workspace: Path) -> dict[str, Any]:
    summary_path = workspace / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json"
    readiness_path = workspace / "scanners" / "rust" / "RUST_SCAN_READINESS.json"
    source_graph_path = workspace / ".auditooor" / "rust_source_graph.json"
    cross_graph_path = workspace / ".auditooor" / "rust_cross_crate_graph.json"
    runtime_path = workspace / ".auditooor" / "rust_runtime_semantic_blockers.json"
    dlt_path = workspace / ".auditooor" / "runtime_dlt_execution_evidence_validator.json"
    summary = load_json(summary_path)
    readiness = load_json(readiness_path)
    source = load_json(source_graph_path)
    cross = load_json(cross_graph_path)
    runtime = load_json(runtime_path)
    dlt = load_json(dlt_path)
    source_meta = source.get("_meta") if isinstance(source, dict) else {}
    cross_meta = cross.get("_meta") if isinstance(cross, dict) else {}
    if not isinstance(source_meta, dict):
        source_meta = {}
    if not isinstance(cross_meta, dict):
        cross_meta = {}
    dlt_summary = dlt.get("summary") if isinstance(dlt, dict) else {}
    runtime_counts = runtime.get("runtime_component_family_counts") if isinstance(runtime, dict) else {}
    readiness_blockers = readiness.get("blockers") if isinstance(readiness, dict) else []
    readiness_roots = readiness.get("roots") if isinstance(readiness, dict) else []
    readiness_missing_tools = readiness.get("missing_tools") if isinstance(readiness, dict) else []
    readiness_tool_available = readiness.get("tool_available") if isinstance(readiness, dict) else {}
    return {
        "scan_summary_present": summary_path.is_file(),
        "scan_summary_path": str(summary_path),
        "readiness_present": readiness_path.is_file(),
        "readiness_path": str(readiness_path),
        "readiness_can_run_scan_rust": bool(readiness.get("can_run_scan_rust")) if isinstance(readiness, dict) else False,
        "readiness_root_count": int(readiness.get("root_count") or 0) if isinstance(readiness, dict) else 0,
        "readiness_roots": readiness_roots if isinstance(readiness_roots, list) else [],
        "readiness_missing_tools": readiness_missing_tools if isinstance(readiness_missing_tools, list) else [],
        "readiness_tool_available": readiness_tool_available if isinstance(readiness_tool_available, dict) else {},
        "readiness_blockers": readiness_blockers if isinstance(readiness_blockers, list) else [],
        "rust_source_graph_present": source_graph_path.is_file(),
        "rust_source_graph_path": str(source_graph_path),
        "rust_source_crate_count": int(
            source_meta.get("crate_count")
            or ((runtime.get("summary") or {}).get("crate_count") if isinstance(runtime.get("summary"), dict) else 0)
            or 0
        )
        if isinstance(runtime, dict)
        else int(source_meta.get("crate_count") or 0),
        "rust_cross_crate_graph_present": cross_graph_path.is_file(),
        "rust_cross_crate_graph_path": str(cross_graph_path),
        "rust_cross_crate_edge_count": int(cross_meta.get("edge_count") or 0),
        "runtime_blockers_present": runtime_path.is_file(),
        "runtime_component_family_counts": runtime_counts if isinstance(runtime_counts, dict) else {},
        "runtime_dlt_validator_present": dlt_path.is_file(),
        "dlt_row_count": int(dlt.get("dlt_row_count") or 0) if isinstance(dlt, dict) else 0,
        "dlt_closure_candidate_count": int(dlt.get("closure_candidate_count") or 0) if isinstance(dlt, dict) else 0,
        "dlt_blocker_counts": dlt_summary.get("blocker_counts") if isinstance(dlt_summary, dict) else {},
        "status": "scan_summary_missing" if not summary_path.is_file() else "scan_summary_present",
        "next_commands": [
            "tools/rust-scan-runner.sh <base_ws> --readiness --strict",
            "python3 tools/engage.py --workspace <base_ws> --stage scan-rust",
            "tools/rust-scan-runner.sh <base_ws>",
            "make rust-runtime-semantic-blockers WS=<base_ws> GENERATE=1 JSON=1",
            "make runtime-dlt-execution-evidence WS=<base_ws> DEMO_FIXTURE=1 JSON=1",
        ],
    }


def scope_rubric_status(workspace: Path) -> dict[str, Any]:
    scope_path = workspace / "SCOPE.md"
    oos_path = workspace / "OOS_PASTED.md"
    rubric_path = workspace / "RUBRIC_COVERAGE.md"
    severity_paths = [
        workspace / "SEVERITY.md",
        workspace / "SEVERITY_SMART_CONTRACTS.md",
        workspace / "SEVERITY_BLOCKCHAIN_DLT.md",
    ]
    severity_ready = [path for path in severity_paths if path.is_file() and _looks_populated(path)]
    impact_ready = bool((rubric_path.is_file() and _looks_populated(rubric_path)) or severity_ready)
    return {
        "scope_present": scope_path.is_file(),
        "scope_populated": scope_path.is_file() and _looks_populated(scope_path),
        "oos_present": oos_path.is_file(),
        "oos_populated": oos_path.is_file() and _looks_populated(oos_path),
        "rubric_coverage_present": rubric_path.is_file(),
        "rubric_coverage_populated": rubric_path.is_file() and _looks_populated(rubric_path),
        "severity_sources_ready": [path.name for path in severity_ready],
        "impact_rubric_ready": impact_ready,
        "smart_contract_rubric_ready": (workspace / "SEVERITY_SMART_CONTRACTS.md").is_file()
        and _looks_populated(workspace / "SEVERITY_SMART_CONTRACTS.md"),
        "blockchain_dlt_rubric_ready": (workspace / "SEVERITY_BLOCKCHAIN_DLT.md").is_file()
        and _looks_populated(workspace / "SEVERITY_BLOCKCHAIN_DLT.md"),
        "status": "ready" if scope_path.is_file() and _looks_populated(scope_path) and oos_path.is_file() and impact_ready else "missing_scope_oos_or_impact_rubric",
        "next_commands": [
            "paste scope/impact/OOS into SCOPE.md, SEVERITY_SMART_CONTRACTS.md, SEVERITY_BLOCKCHAIN_DLT.md, and RUBRIC_COVERAGE.md",
            "python3 tools/operator-oos-import.py --workspace <base_ws> --source-url <program_url> --from-file <oos_paste.txt>",
            "python3 tools/engage.py --workspace <base_ws> --stage intake-baseline",
        ],
    }


def root_role_status(
    workspace: Path,
    *,
    base_root: Path | None,
    smart_contract_roots: Sequence[Path] | None,
    rust_roots: Sequence[Path] | None,
    reth_roots: Sequence[Path] | None,
    tee_roots: Sequence[Path] | None,
    zk_roots: Sequence[Path] | None,
) -> dict[str, Any]:
    declared_payload = load_json(workspace / ".auditooor" / "project_source_root_readiness.json")
    declared_roots = declared_payload.get("roots") if isinstance(declared_payload, dict) else []
    if not isinstance(declared_roots, list):
        declared_roots = []
    declared_ready = [
        root for root in declared_roots if isinstance(root, dict) and root.get("usable")
    ]
    declared_smart_files = sum(_declared_language_count(root, "solidity", ".sol") for root in declared_ready)
    declared_rust_files = sum(_declared_language_count(root, "rust", ".rs") for root in declared_ready)
    declared_smart_labels = _declared_labels_for_language(declared_ready, "solidity", ".sol")
    declared_rust_labels = _declared_labels_for_language(declared_ready, "rust", ".rs")

    base = base_root.expanduser().resolve() if base_root else None
    smart_paths = _resolve_optional_roots(smart_contract_roots)
    rust_paths = _resolve_optional_roots(rust_roots)
    reth_paths = _resolve_optional_roots(reth_roots)
    tee_paths = _resolve_optional_roots(tee_roots)
    zk_paths = _resolve_optional_roots(zk_roots)
    if base:
        rust_paths = [base, *rust_paths]

    smart_statuses = [_root_status(path) for path in smart_paths]
    rust_statuses = [_root_status(path) for path in rust_paths]
    reth_statuses = [_root_status(path) for path in reth_paths]
    tee_statuses = [_root_status(path) for path in tee_paths]
    zk_statuses = [_root_status(path) for path in zk_paths]
    smart_ready = bool(declared_smart_files or any(item["has_smart_contract_source"] for item in smart_statuses))
    rust_ready = bool(declared_rust_files or any(item["has_rust_source"] for item in rust_statuses))
    return {
        "declared_ready_root_count": len(declared_ready),
        "declared_sample_solidity_files": declared_smart_files,
        "declared_sample_rust_files": declared_rust_files,
        "declared_smart_contract_root_labels": declared_smart_labels,
        "declared_rust_dlt_root_labels": declared_rust_labels,
        "smart_contract_roots": smart_statuses,
        "rust_dlt_roots": rust_statuses,
        "reth_roots": reth_statuses,
        "tee_roots": tee_statuses,
        "zk_roots": zk_statuses,
        "smart_contract_roots_ready": smart_ready,
        "rust_dlt_roots_ready": rust_ready,
        "reth_roots_ready": any(item["has_rust_source"] for item in reth_statuses),
        "tee_roots_ready": any(item["has_rust_source"] or item["solidity_files"] for item in tee_statuses),
        "zk_roots_ready": any(item["rust_files"] or item["cairo_files"] or item["solidity_files"] for item in zk_statuses),
        "status": "ready" if smart_ready and rust_ready else "missing_smart_or_rust_roots",
        "next_commands": [
            "mkdir -p <base_ws>/external",
            "git clone --recurse-submodules <base_contracts_or_op_contracts_repo_url> <base_ws>/external/base-contracts",
            "git clone --recurse-submodules <base_node_or_reth_repo_url> <base_ws>/external/base-reth",
            "git -C <base_ws>/external/base-contracts fetch --all --tags --prune && git -C <base_ws>/external/base-contracts checkout <reviewed_commit_or_tag>",
            "git -C <base_ws>/external/base-reth fetch --all --tags --prune && git -C <base_ws>/external/base-reth checkout <reviewed_commit_or_tag>",
            "git clone --recurse-submodules <tee_or_zk_repo_url_if_in_scope> <base_ws>/external/<component>",
            "make project-source-root-declaration WS=<base_ws> ENTRY=base-contracts=external/base-contracts REPLACE=1 JSON=1",
            "make project-source-root-declaration WS=<base_ws> ENTRY=base-reth=external/base-reth JSON=1",
            "make project-source-root-readiness WS=<base_ws> JSON=1",
        ],
    }


def live_proof_status(workspace: Path) -> dict[str, Any]:
    router_path = workspace / ".auditooor" / "live_topology_real_proof_input_router.json"
    materializer_path = workspace / ".auditooor" / "live_topology_manual_proof_materializer.json"
    live_checks_path = workspace / "live_topology_checks.json"
    router = load_json(router_path)
    materializer = load_json(materializer_path)
    ready_pairs = int(router.get("same_block_ready_pair_count") or router.get("same_block_real_proof_ready_pairs") or 0) if isinstance(router, dict) else 0
    materialized_rows = int(materializer.get("materialized_row_count") or materializer.get("rows_materialized") or 0) if isinstance(materializer, dict) else 0
    return {
        "live_topology_checks_present": live_checks_path.is_file(),
        "real_input_router_present": router_path.is_file(),
        "manual_proof_materializer_present": materializer_path.is_file(),
        "same_block_ready_pair_count": ready_pairs,
        "materialized_manual_proof_rows": materialized_rows,
        "rpc_env_required": "MAINNET_RPC_URL or Base RPC equivalent for live-state/live-topology capture",
        "status": "ready" if live_checks_path.is_file() and ready_pairs else "missing_real_same_block_inputs",
        "next_commands": [
            "python3 tools/engage.py --workspace <base_ws> --stage live-checks",
            "make live-topology-real-proof-input-router WS=<base_ws> JSON=1",
            "make live-topology-manual-proof-materializer WS=<base_ws> JSON=1",
            "python3 tools/live-check-runner.py --workspace <base_ws> --import-manual-proofs",
            "make live-topology-proof-executor WS=<base_ws> JSON=1",
        ],
    }


def audit_stage_plan(workspace: Path) -> dict[str, Any]:
    artifacts = {
        "intake_baseline": workspace / "INTAKE_BASELINE.json",
        "deployment_topology": workspace / "deployment_topology.json",
        "live_topology_checks": workspace / "live_topology_checks.json",
        "mining_priorities": workspace / "swarm" / "mining_priorities.json",
        "semantic_graph": workspace / ".auditooor" / "semantic_graph.json",
        "rust_scan_summary": workspace / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json",
    }
    present = {name: path.is_file() for name, path in artifacts.items()}
    return {
        "artifact_presence": present,
        "status": "ready_to_run_initial_chain" if present["intake_baseline"] else "intake_baseline_not_run_or_stale",
        "no_network_or_git_executed": True,
        "recommended_commands": [
            "python3 tools/engage.py --workspace <base_ws> --stage intake-baseline",
            "make semantic-graph WS=<base_ws>",
            "python3 tools/engage.py --workspace <base_ws> --stage orient",
            "python3 tools/engage.py --workspace <base_ws> --stage live-checks",
            "python3 tools/engage.py --workspace <base_ws> --stage env-check",
            "python3 tools/engage.py --workspace <base_ws> --stage scan-rust",
            "python3 tools/engage.py --workspace <base_ws> --stage mine-prioritize",
            "make rust-base-readiness WS=<base_ws> BASE_ROOT=<base_ws>/external/base-reth JSON=1",
            "make critical-hunt WS=<base_ws>",
            "python3 tools/engage.py --workspace <base_ws> --stage mine-briefs",
        ],
        "base_scan_start_condition": "scope/OOS/rubric pasted, source roots declared, fresh repos cloned/fetched/pinned, and scan-rust/runtime/live readiness gates regenerated.",
    }


def project_source_status(workspace: Path) -> dict[str, Any]:
    readiness_path = workspace / ".auditooor" / "project_source_root_readiness.json"
    payload = load_json(readiness_path)
    ready = int(payload.get("ready_root_count") or 0) if isinstance(payload, dict) else 0
    declared = int(payload.get("declared_root_count") or 0) if isinstance(payload, dict) else 0
    return {
        "readiness_present": readiness_path.is_file(),
        "readiness_path": str(readiness_path),
        "declared_root_count": declared,
        "ready_root_count": ready,
        "source_file_count": int(payload.get("source_file_count") or 0) if isinstance(payload, dict) else 0,
        "status": "ready" if ready else "no_ready_project_source_roots",
        "next_commands": [
            "make project-source-root-declaration WS=<base_ws> ENTRY=base=external/base REPLACE=1 JSON=1",
            "make project-source-root-readiness WS=<base_ws> JSON=1",
            "make impact-binding-source-import-readiness WS=<base_ws> JSON=1",
            "make execution-manifest-proof-readiness WS=<base_ws> JSON=1",
        ],
    }


def base_refresh_plan(workspace: Path, base_root: Path | None) -> dict[str, Any]:
    root = base_root.expanduser().resolve() if base_root else None
    root_exists = bool(root and root.exists())
    cargo_count = _count_files(root, ["Cargo.toml"]) if root else 0
    source_count = _count_files(root, ["*.rs"]) if root else 0
    commands = [
        "mkdir -p <base_ws>/external",
        "git clone --recurse-submodules <base_contracts_or_op_contracts_repo_url> <base_ws>/external/base-contracts",
        "git clone --recurse-submodules <base_node_or_reth_repo_url> <base_ws>/external/base-reth",
        "git -C <base_ws>/external/base-contracts fetch --all --tags --prune && git -C <base_ws>/external/base-contracts checkout <reviewed_commit_or_tag>",
        "git -C <base_ws>/external/base-reth fetch --all --tags --prune && git -C <base_ws>/external/base-reth checkout <reviewed_commit_or_tag>",
        "pbpaste > <base_ws>/SCOPE.md  # or write the pasted in-scope asset text explicitly",
        "pbpaste | python3 tools/operator-oos-import.py --workspace <base_ws>",
        "write populated <base_ws>/SEVERITY_SMART_CONTRACTS.md, <base_ws>/SEVERITY_BLOCKCHAIN_DLT.md, and <base_ws>/RUBRIC_COVERAGE.md from the bounty impact rules",
        "make project-source-root-declaration WS=<base_ws> ENTRY=base-contracts=external/base-contracts REPLACE=1 JSON=1",
        "make project-source-root-declaration WS=<base_ws> ENTRY=base-reth=external/base-reth JSON=1",
        "make project-source-root-readiness WS=<base_ws> JSON=1",
        "python3 tools/engage.py --workspace <base_ws> --stage intake-baseline",
        "make semantic-graph WS=<base_ws>",
        "python3 tools/engage.py --workspace <base_ws> --stage orient",
        "python3 tools/engage.py --workspace <base_ws> --stage live-checks",
        "python3 tools/engage.py --workspace <base_ws> --stage scan-rust",
        "python3 tools/engage.py --workspace <base_ws> --stage mine-prioritize",
        "make rust-base-readiness WS=<base_ws> BASE_ROOT=<base_ws>/external/base-reth SMART_CONTRACT_ROOT=<base_ws>/external/base-contracts RETH_ROOT=<base_ws>/external/base-reth JSON=1",
    ]
    return {
        "provided_base_root": str(root) if root else "",
        "provided_base_root_exists": root_exists,
        "cargo_manifest_count": cargo_count,
        "rust_source_file_count": source_count,
        "status": "base_root_present" if root_exists else "base_root_not_provided_or_missing",
        "network_not_used": True,
        "exact_refresh_commands": commands,
        "safety_notes": [
            "Run clone/fetch in a separate Base audit workspace, not in this PR560 integration worktree.",
            "Pin and record the reviewed commit before claiming scan freshness.",
            "Declare the cloned source root before source-proof or harness binding reducers.",
            "Do not promote Base-only evidence without a hermetic or non-Base validation where the known-limitation row requires workspace neutrality.",
        ],
    }


def build_payload(
    workspace: Path,
    *,
    zkbugs_root: Path | None = None,
    rustbugs_root: Path | None = None,
    base_root: Path | None = None,
    smart_contract_roots: Sequence[Path] | None = None,
    rust_roots: Sequence[Path] | None = None,
    reth_roots: Sequence[Path] | None = None,
    tee_roots: Sequence[Path] | None = None,
    zk_roots: Sequence[Path] | None = None,
) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    zk = zkbugs_status(workspace, zkbugs_root)
    rb = rustbugs_status(workspace, rustbugs_root)
    rs = rust_scan_status(workspace)
    ps = project_source_status(workspace)
    sr = scope_rubric_status(workspace)
    roots = root_role_status(
        workspace,
        base_root=base_root,
        smart_contract_roots=smart_contract_roots,
        rust_roots=rust_roots,
        reth_roots=reth_roots,
        tee_roots=tee_roots,
        zk_roots=zk_roots,
    )
    live = live_proof_status(workspace)
    audit = audit_stage_plan(workspace)
    base = base_refresh_plan(workspace, base_root)
    blockers = []
    if not zk["fully_mined"]:
        blockers.append("zkbugs_corpus_not_fully_ingested_or_queued")
    if not rb["fully_mined"]:
        blockers.append("rustbugs_corpus_not_supported_or_not_ingested")
    if not rs["scan_summary_present"]:
        blockers.append("scan_rust_summary_missing")
    for blocker in rs["readiness_blockers"]:
        blockers.append(f"scan_rust_readiness_{blocker}")
    if not rs["runtime_dlt_validator_present"] or rs["dlt_closure_candidate_count"] == 0:
        blockers.append("runtime_dlt_execution_evidence_unproved")
    if ps["ready_root_count"] == 0:
        blockers.append("project_source_roots_missing")
    if not base["provided_base_root_exists"]:
        blockers.append("fresh_base_root_not_declared")
    if not sr["scope_populated"]:
        blockers.append("scope_input_missing_or_placeholder")
    if not sr["impact_rubric_ready"]:
        blockers.append("impact_rubric_missing_or_placeholder")
    if not sr["oos_populated"]:
        blockers.append("operator_oos_missing")
    if not roots["smart_contract_roots_ready"]:
        blockers.append("smart_contract_roots_missing")
    if not roots["rust_dlt_roots_ready"]:
        blockers.append("rust_dlt_roots_missing")
    if not live["live_topology_checks_present"]:
        blockers.append("live_topology_checks_missing")
    ready_for_base_scan = not any(
        b in blockers
        for b in (
            "scan_rust_summary_missing",
            "project_source_roots_missing",
            "fresh_base_root_not_declared",
            "scope_input_missing_or_placeholder",
            "impact_rubric_missing_or_placeholder",
            "operator_oos_missing",
            "smart_contract_roots_missing",
            "rust_dlt_roots_missing",
        )
    )
    return {
        "schema": SCHEMA,
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "ready_for_fresh_base_scan": ready_for_base_scan,
        "ready_for_proof_promotion": False,
        "blockers": blockers,
        "blocker_counts": dict(sorted(Counter(blockers).items())),
        "zkbugs": zk,
        "rustbugs": rb,
        "rust_scan": rs,
        "scope_rubric": sr,
        "project_source_roots": ps,
        "root_roles": roots,
        "live_proof": live,
        "audit_stage_plan": audit,
        "base_refresh": base,
        "operator_bootstrap_checklist": [
            "1. Create or reuse a dedicated Base audit workspace outside this PR560 worktree.",
            "2. Paste exact Base scope, impact/severity, and OOS text into SCOPE.md, SEVERITY_SMART_CONTRACTS.md, SEVERITY_BLOCKCHAIN_DLT.md, RUBRIC_COVERAGE.md, and OOS_PASTED.md.",
            "3. Clone/fetch fresh smart-contract and Rust/DLT roots under <base_ws>/external/, pin reviewed commits, and declare both roots.",
            "4. Run project-source-root-readiness and confirm at least one Solidity root and one Rust/DLT root are ready.",
            "5. Run intake-baseline, semantic-graph, orient, live-checks, scan-rust, and mine-prioritize in that order.",
            "6. Re-run rust-base-readiness; only start mining when smart_contract_roots_missing, rust_dlt_roots_missing, scan_rust_summary_missing, scope_input_missing_or_placeholder, impact_rubric_missing_or_placeholder, and operator_oos_missing are absent.",
        ],
        "operator_answer": {
            "mined_all_rustbugs": rb["fully_mined"],
            "mined_all_zkbugs": zk["fully_mined"],
            "rust_scans_fetch_all_code": bool(rs["scan_summary_present"] and rs["rust_source_graph_present"] and rs["rust_cross_crate_graph_present"]),
            "cross_contract_or_cross_crate_ready": bool(rs["rust_cross_crate_graph_present"]),
            "scope_impact_oos_ready": bool(sr["scope_populated"] and sr["impact_rubric_ready"] and sr["oos_populated"]),
            "smart_contract_roots_ready": roots["smart_contract_roots_ready"],
            "rust_dlt_roots_ready": roots["rust_dlt_roots_ready"],
            "base_reth_tee_zk_deep_runtime_ready": bool(
                roots["reth_roots_ready"]
                and (roots["tee_roots_ready"] or roots["zk_roots_ready"])
                and rs["runtime_dlt_validator_present"]
                and rs["rust_cross_crate_graph_present"]
            ),
            "live_same_block_inputs_ready": live["same_block_ready_pair_count"] > 0,
            "can_run_base_now": ready_for_base_scan,
        },
        "proof_boundary": "Readiness only. This artifact does not claim exploit impact, source proof, OOS clearance, severity, or submission readiness.",
    }


def render_markdown(payload: dict[str, Any]) -> str:
    op = payload["operator_answer"]
    lines = [
        "# Rust / Base Scan Readiness",
        "",
        "## Direct Answers",
        "",
        f"- Mined all RustBugs: `{op['mined_all_rustbugs']}`",
        f"- Mined all zkBugs: `{op['mined_all_zkbugs']}`",
        f"- Rust scan has source + cross-crate artifacts: `{op['rust_scans_fetch_all_code']}`",
        f"- Cross-crate readiness present: `{op['cross_contract_or_cross_crate_ready']}`",
        f"- Scope / impact / OOS ready: `{op['scope_impact_oos_ready']}`",
        f"- Smart-contract roots ready: `{op['smart_contract_roots_ready']}`",
        f"- Rust / DLT roots ready: `{op['rust_dlt_roots_ready']}`",
        f"- Base/reth/TEE/ZK deep runtime ready: `{op['base_reth_tee_zk_deep_runtime_ready']}`",
        f"- Live same-block inputs ready: `{op['live_same_block_inputs_ready']}`",
        f"- Can run fresh Base scan now: `{op['can_run_base_now']}`",
        "",
        "## Blockers",
        "",
    ]
    for blocker in payload["blockers"] or ["none"]:
        lines.append(f"- `{blocker}`")
    lines.extend([
        "",
        "## Corpus Status",
        "",
        f"- zkBugs: `{payload['zkbugs']['status']}`; repo-content records `{payload['zkbugs']['repo_content_records']}`; index records `{payload['zkbugs']['total_records']}`; queue rows `{payload['zkbugs']['provider_queue_rows']}`; route status `{payload['zkbugs']['route_completeness_status']}`; detector/invariant/replay rows `{payload['zkbugs']['detector_queue_rows']}`/`{payload['zkbugs']['invariant_queue_rows']}`/`{payload['zkbugs']['replay_queue_rows']}`; provider pull recorded `{payload['zkbugs']['provider_pull_recorded']}`",
        f"- RustBugs: `{payload['rustbugs']['status']}`; ingestor present `{payload['rustbugs']['ingestor_present']}`; records `{payload['rustbugs']['record_count']}`",
        "",
        "## Rust / DLT Status",
        "",
        f"- scan-rust summary present: `{payload['rust_scan']['scan_summary_present']}`",
        f"- scan-rust readiness present: `{payload['rust_scan']['readiness_present']}`; can run `{payload['rust_scan']['readiness_can_run_scan_rust']}`; roots `{payload['rust_scan']['readiness_root_count']}`; missing tools `{', '.join(payload['rust_scan']['readiness_missing_tools']) or 'none'}`",
        f"- source graph present: `{payload['rust_scan']['rust_source_graph_present']}`; crates `{payload['rust_scan']['rust_source_crate_count']}`",
        f"- cross-crate graph present: `{payload['rust_scan']['rust_cross_crate_graph_present']}`; edges `{payload['rust_scan']['rust_cross_crate_edge_count']}`",
        f"- DLT rows: `{payload['rust_scan']['dlt_row_count']}`; closure candidates `{payload['rust_scan']['dlt_closure_candidate_count']}`",
        f"- project source roots ready: `{payload['project_source_roots']['ready_root_count']}`",
        "",
        "## Scope / Roots / Live Preconditions",
        "",
        f"- scope populated: `{payload['scope_rubric']['scope_populated']}`",
        f"- impact rubric ready: `{payload['scope_rubric']['impact_rubric_ready']}`",
        f"- OOS pasted: `{payload['scope_rubric']['oos_populated']}`",
        f"- declared ready source roots: `{payload['root_roles']['declared_ready_root_count']}`",
        f"- smart roots ready: `{payload['root_roles']['smart_contract_roots_ready']}`",
        f"- Rust/DLT roots ready: `{payload['root_roles']['rust_dlt_roots_ready']}`",
        f"- reth roots ready: `{payload['root_roles']['reth_roots_ready']}`",
        f"- TEE roots ready: `{payload['root_roles']['tee_roots_ready']}`",
        f"- ZK roots ready: `{payload['root_roles']['zk_roots_ready']}`",
        f"- live topology checks present: `{payload['live_proof']['live_topology_checks_present']}`",
        f"- same-block live input pairs ready: `{payload['live_proof']['same_block_ready_pair_count']}`",
        "",
        "## Audit Command Plan",
        "",
    ])
    for command in payload["audit_stage_plan"]["recommended_commands"]:
        lines.append(f"- `{command}`")
    lines.extend([
        "",
        "## Operator Bootstrap Checklist",
        "",
    ])
    for item in payload["operator_bootstrap_checklist"]:
        lines.append(f"- {item}")
    lines.extend([
        "",
        "## Base Refresh Commands",
        "",
    ])
    for command in payload["base_refresh"]["exact_refresh_commands"]:
        lines.append(f"- `{command}`")
    lines.extend([
        "",
        "## Boundary",
        "",
        payload["proof_boundary"],
    ])
    return "\n".join(lines) + "\n"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--zkbugs-root", type=Path)
    parser.add_argument("--rustbugs-root", type=Path)
    parser.add_argument("--base-root", type=Path)
    parser.add_argument("--smart-contract-root", action="append", type=Path, default=[])
    parser.add_argument("--rust-root", action="append", type=Path, default=[])
    parser.add_argument("--reth-root", action="append", type=Path, default=[])
    parser.add_argument("--tee-root", action="append", type=Path, default=[])
    parser.add_argument("--zk-root", action="append", type=Path, default=[])
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    payload = build_payload(
        workspace,
        zkbugs_root=args.zkbugs_root,
        rustbugs_root=args.rustbugs_root,
        base_root=args.base_root,
        smart_contract_roots=args.smart_contract_root,
        rust_roots=args.rust_root,
        reth_roots=args.reth_root,
        tee_roots=args.tee_root,
        zk_roots=args.zk_root,
    )
    out_json = args.out_json or workspace / DEFAULT_OUT
    out_md = args.out_md or workspace / DEFAULT_OUT_MD
    write_json(out_json, payload)
    write_text(out_md, render_markdown(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
