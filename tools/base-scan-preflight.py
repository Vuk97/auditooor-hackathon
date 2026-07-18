#!/usr/bin/env python3
"""Fail-closed preflight before starting a fresh Base scan.

This command is intentionally read-only except for writing its JSON/Markdown
artifact. It answers the operator question: after pasting scope/OOS and
declaring source roots, what is still blocking the Base scan, and what exact
command should run next?
"""

from __future__ import annotations

import argparse
import json
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, NamedTuple, Sequence


SCHEMA = "auditooor.base_scan_preflight.v1"
DEFAULT_OUT_JSON = ".auditooor/base_scan_preflight.json"
DEFAULT_OUT_MD = ".auditooor/base_scan_preflight.md"
SOURCE_SUFFIXES = {".sol", ".rs", ".cairo", ".move", ".vy"}
PLACEHOLDER_MARKERS = (
    "todo",
    "placeholder",
    "paste here",
    "paste scope",
    "paste oos",
    "copy/paste",
    "copy from bounty",
    "rubric unavailable",
    "scope unavailable",
    "tbd",
)
RUST_DLT_SCOPE_MARKERS = (
    "rust",
    "cargo",
    "reth",
    "op-node",
    "consensus",
    "execution client",
    "execution layer",
    "blockchain/dlt",
    "blockchain dlt",
)
ZK_SCOPE_MARKERS = (
    "zk",
    "zero-knowledge",
    "zero knowledge",
    "zkvm",
    "zk-vm",
    "prover",
    "verifier",
    "circuit",
    "plonk",
    "stark",
    "snark",
)


def load_json(path: Path) -> tuple[Any, str]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), ""
    except FileNotFoundError:
        return {}, "missing"
    except json.JSONDecodeError as exc:
        return {}, f"invalid_json: {exc}"


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def looks_populated(path: Path) -> bool:
    text = read_text(path)
    if len(text.strip()) < 20:
        return False
    lowered = text.lower()
    return not any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def rel(workspace: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return str(path)


def count_sources(root: Path, workspace: Path) -> dict[str, int]:
    counts = {".sol": 0, ".rs": 0, ".cairo": 0, ".move": 0, ".vy": 0}
    if not root.is_dir():
        return counts
    excluded_parts = {".git", "node_modules", "target", "out", "cache", "artifacts", "vendor"}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        if any(part in excluded_parts for part in path.parts):
            continue
        counts[path.suffix] += 1
    return counts


def path_from_cli(workspace: Path, path: Path) -> Path:
    expanded = path.expanduser()
    return expanded if expanded.is_absolute() else workspace / expanded


def gate(
    gate_id: str,
    title: str,
    passed: bool,
    *,
    details: dict[str, Any] | None = None,
    blockers: list[str] | None = None,
    next_commands: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": gate_id,
        "title": title,
        "status": "PASS" if passed else "BLOCKED",
        "blockers": [] if passed else list(blockers or []),
        "next_commands": [] if passed else list(next_commands or []),
        "details": details or {},
    }


def skipped_gate(gate_id: str, title: str, reason: str, *, details: dict[str, Any] | None = None) -> dict[str, Any]:
    merged_details = dict(details or {})
    merged_details["skip_reason"] = reason
    return {
        "id": gate_id,
        "title": title,
        "status": "SKIPPED",
        "blockers": [],
        "next_commands": [],
        "details": merged_details,
    }


class AssetContext(NamedTuple):
    solidity_signals: int
    rust_dlt_signals: int
    zk_scope_indicated: bool
    rust_dlt_scope_indicated: bool
    intake_text_paths: tuple[str, ...]

    @property
    def needs_rust_dlt(self) -> bool:
        return self.rust_dlt_signals > 0 or self.rust_dlt_scope_indicated

    @property
    def needs_zk(self) -> bool:
        return self.zk_scope_indicated


def asset_context_details(context: AssetContext) -> dict[str, Any]:
    return dict(context._asdict())


def _marker_present(text: str, markers: Sequence[str]) -> bool:
    lowered = text.lower()
    return any(re.search(rf"(?<![a-z0-9_-]){re.escape(marker)}(?![a-z0-9_-])", lowered) for marker in markers)


def _intake_text(workspace: Path) -> tuple[str, tuple[str, ...]]:
    paths = [
        workspace / "SCOPE.md",
        workspace / "SEVERITY.md",
        workspace / "SEVERITY_SMART_CONTRACTS.md",
        workspace / "SEVERITY_BLOCKCHAIN_DLT.md",
        workspace / "RUBRIC_COVERAGE.md",
        workspace / "OOS_PASTED.md",
    ]
    texts: list[str] = []
    populated_paths: list[str] = []
    for path in paths:
        if looks_populated(path):
            texts.append(read_text(path))
            populated_paths.append(str(path))
    return "\n".join(texts), tuple(populated_paths)


def _source_signals(
    workspace: Path,
    smart_roots: Sequence[Path],
    rust_roots: Sequence[Path],
) -> tuple[int, int, list[dict[str, Any]], list[dict[str, Any]], int, str]:
    readiness_path = workspace / ".auditooor" / "project_source_root_readiness.json"
    payload, error = load_json(readiness_path)
    roots = payload.get("roots") if isinstance(payload, dict) else []
    if not isinstance(roots, list):
        roots = []
    ready_roots = [root for root in roots if isinstance(root, dict) and root.get("usable")]

    declared_sol = 0
    declared_rs = 0
    for root in ready_roots:
        presence = root.get("language_presence") if isinstance(root.get("language_presence"), dict) else {}
        suffix_counts = root.get("suffix_counts") if isinstance(root.get("suffix_counts"), dict) else {}
        declared_sol += int(presence.get("solidity") or suffix_counts.get(".sol") or 0)
        declared_rs += int(presence.get("rust") or suffix_counts.get(".rs") or 0)

    cli_smart = []
    cli_rust = []
    for item in smart_roots:
        root = path_from_cli(workspace, item)
        counts = count_sources(root, workspace)
        cli_smart.append({"path": str(root), "exists": root.is_dir(), "source_counts": counts})
        declared_sol += counts[".sol"]
        declared_rs += counts[".rs"]
    for item in rust_roots:
        root = path_from_cli(workspace, item)
        counts = count_sources(root, workspace)
        has_cargo = (root / "Cargo.toml").is_file()
        cli_rust.append({"path": str(root), "exists": root.is_dir(), "source_counts": counts, "cargo_toml": has_cargo})
        declared_rs += counts[".rs"] + (1 if has_cargo else 0)

    return declared_sol, declared_rs, cli_smart, cli_rust, len(ready_roots), error


def asset_context(
    workspace: Path,
    smart_contract_roots: Sequence[Path],
    rust_dlt_roots: Sequence[Path],
) -> AssetContext:
    declared_sol, declared_rs, _, _, _, _ = _source_signals(workspace, smart_contract_roots, rust_dlt_roots)
    intake, paths = _intake_text(workspace)
    dlt_severity_populated = looks_populated(workspace / "SEVERITY_BLOCKCHAIN_DLT.md")
    return AssetContext(
        solidity_signals=declared_sol,
        rust_dlt_signals=declared_rs,
        zk_scope_indicated=_marker_present(intake, ZK_SCOPE_MARKERS),
        rust_dlt_scope_indicated=dlt_severity_populated or _marker_present(intake, RUST_DLT_SCOPE_MARKERS),
        intake_text_paths=paths,
    )


def scope_gate(workspace: Path, context: AssetContext | None = None) -> dict[str, Any]:
    paths = {
        "scope": workspace / "SCOPE.md",
        "severity": workspace / "SEVERITY.md",
        "smart_severity": workspace / "SEVERITY_SMART_CONTRACTS.md",
        "dlt_severity": workspace / "SEVERITY_BLOCKCHAIN_DLT.md",
        "rubric": workspace / "RUBRIC_COVERAGE.md",
        "oos_pasted": workspace / "OOS_PASTED.md",
        "oos_checklist": workspace / "OOS_CHECKLIST.md",
    }
    populated = {name: looks_populated(path) for name, path in paths.items()}
    split_severity_ready = populated["smart_severity"] and populated["dlt_severity"]
    severity_ready = populated["severity"] or split_severity_ready
    passed = populated["scope"] and severity_ready and populated["rubric"] and populated["oos_pasted"]
    blockers: list[str] = []
    if not populated["scope"]:
        blockers.append("SCOPE.md missing, empty, or placeholder")
    if not severity_ready:
        if context and not context.needs_rust_dlt:
            blockers.append("severity impact rules missing; expected populated SEVERITY.md or SEVERITY_SMART_CONTRACTS.md")
        else:
            blockers.append("severity impact rules missing; Base expects split smart-contract and Blockchain/DLT severity or populated SEVERITY.md")
    if not populated["rubric"]:
        blockers.append("RUBRIC_COVERAGE.md missing, empty, or placeholder")
    if not populated["oos_pasted"]:
        blockers.append("OOS_PASTED.md missing; paste the program OOS text before scan")
    return gate(
        "scope_impact_oos",
        "Scope, impact, severity, rubric, and pasted OOS",
        passed,
        details={
            "paths": {name: str(path) for name, path in paths.items()},
            "populated": populated,
            "split_severity_ready": split_severity_ready,
            "severity_ready": severity_ready,
        },
        blockers=blockers,
        next_commands=[
            "pbpaste > <base_ws>/SCOPE.md",
            "pbpaste > <base_ws>/OOS_PASTED.md",
            (
                "write populated <base_ws>/SEVERITY_SMART_CONTRACTS.md and <base_ws>/SEVERITY_BLOCKCHAIN_DLT.md from the bounty impact rules"
                if context is None or context.needs_rust_dlt
                else "write populated <base_ws>/SEVERITY.md or <base_ws>/SEVERITY_SMART_CONTRACTS.md from the bounty impact rules"
            ),
            "write populated <base_ws>/RUBRIC_COVERAGE.md with every in-scope impact class mapped",
            "python3 tools/operator-oos-import.py <base_ws>",
            "python3 tools/engage.py --workspace <base_ws> --stage intake-baseline",
        ],
    )


def project_source_gate(
    workspace: Path,
    smart_roots: Sequence[Path],
    rust_roots: Sequence[Path],
    context: AssetContext,
) -> dict[str, Any]:
    readiness_path = workspace / ".auditooor" / "project_source_root_readiness.json"
    declared_sol, declared_rs, cli_smart, cli_rust, ready_root_count, error = _source_signals(workspace, smart_roots, rust_roots)

    rust_ready = declared_rs > 0 if context.needs_rust_dlt else True
    passed = readiness_path.is_file() and not error and ready_root_count > 0 and declared_sol > 0 and rust_ready
    blockers: list[str] = []
    if not readiness_path.is_file():
        blockers.append(".auditooor/project_source_root_readiness.json missing")
    if error and error != "missing":
        blockers.append(error)
    if not ready_root_count:
        blockers.append("no ready declared project source roots")
    if declared_sol <= 0:
        blockers.append("no Solidity smart-contract source root declared")
    if context.needs_rust_dlt and declared_rs <= 0:
        blockers.append("no Rust/DLT source root declared")
    return gate(
        "source_roots",
        "Fresh smart-contract and Rust/DLT source roots",
        passed,
        details={
            "readiness_path": str(readiness_path),
            "ready_root_count": ready_root_count,
            "declared_solidity_signals": declared_sol,
            "declared_rust_dlt_signals": declared_rs,
            "rust_dlt_scope_indicated": context.rust_dlt_scope_indicated,
            "rust_dlt_required": context.needs_rust_dlt,
            "cli_smart_contract_roots": cli_smart,
            "cli_rust_dlt_roots": cli_rust,
        },
        blockers=blockers,
        next_commands=[
            "mkdir -p <base_ws>/external",
            "git clone --recurse-submodules <base_contracts_or_op_contracts_repo_url> <base_ws>/external/base-contracts",
            "git -C <base_ws>/external/base-contracts checkout <reviewed_commit_or_tag>",
            "make project-source-root-declaration WS=<base_ws> ENTRY=base-contracts=external/base-contracts REPLACE=1 JSON=1",
            *(
                [
                    "git clone --recurse-submodules <base_reth_or_node_repo_url> <base_ws>/external/base-reth",
                    "git -C <base_ws>/external/base-reth checkout <reviewed_commit_or_tag>",
                    "make project-source-root-declaration WS=<base_ws> ENTRY=base-reth=external/base-reth JSON=1",
                ]
                if context.needs_rust_dlt
                else []
            ),
            "make project-source-root-readiness WS=<base_ws> JSON=1",
        ],
    )


def artifact_presence_gate(
    workspace: Path,
    gate_id: str,
    title: str,
    json_rel: str,
    md_rel: str | None,
    *,
    row_keys: Sequence[str] = (),
    next_commands: Sequence[str],
) -> dict[str, Any]:
    json_path = workspace / json_rel
    md_path = workspace / md_rel if md_rel else None
    payload, error = load_json(json_path)
    row_count = 0
    if isinstance(payload, dict):
        for key in row_keys:
            value = payload.get(key)
            if isinstance(value, list):
                row_count = max(row_count, len(value))
            elif isinstance(value, int):
                row_count = max(row_count, value)
    present = json_path.is_file() and not error and bool(payload)
    md_present = True if md_path is None else md_path.is_file()
    has_rows = True if not row_keys else row_count > 0
    passed = present and md_present and has_rows
    blockers: list[str] = []
    if not json_path.is_file():
        blockers.append(f"{json_rel} missing")
    elif error:
        blockers.append(error)
    elif not payload:
        blockers.append(f"{json_rel} is empty")
    if md_path is not None and not md_path.is_file():
        blockers.append(f"{md_rel} missing")
    if row_keys and row_count <= 0:
        blockers.append(f"{json_rel} has no rows/counts for {', '.join(row_keys)}")
    return gate(
        gate_id,
        title,
        passed,
        details={
            "json_path": str(json_path),
            "md_path": str(md_path) if md_path else "",
            "json_present": json_path.is_file(),
            "md_present": md_present,
            "row_count": row_count,
            "json_error": error,
        },
        blockers=blockers,
        next_commands=list(next_commands),
    )


def scan_rust_gate(workspace: Path) -> dict[str, Any]:
    return artifact_presence_gate(
        workspace,
        "scan_rust_summary",
        "Rust/DLT scan-rust summary",
        "scanners/rust/SCAN_RUST_SUMMARY.json",
        "scanners/rust/SCAN_RUST_SUMMARY.md",
        next_commands=[
            "python3 tools/engage.py --workspace <base_ws> --stage scan-rust",
            "tools/rust-scan-runner.sh <base_ws> --strict",
        ],
    )


def semantic_graph_gate(workspace: Path) -> dict[str, Any]:
    return artifact_presence_gate(
        workspace,
        "semantic_graph",
        "Semantic graph",
        ".auditooor/semantic_graph.json",
        ".auditooor/semantic_graph.md",
        next_commands=[
            "make semantic-graph WS=<base_ws>",
            "make semantic-scanner-inventory WS=<base_ws> JSON=1",
        ],
    )


def live_topology_gate(workspace: Path) -> dict[str, Any]:
    requirements_path = workspace / ".auditooor" / "live_topology_proof_requirements.json"
    generated_path = workspace / "monitoring" / "live_topology_proof_requirements.generated.json"
    requirements, requirements_error = load_json(requirements_path)
    generated, generated_error = load_json(generated_path)

    req_rows = requirements.get("requirements") if isinstance(requirements, dict) else None
    generated_checks = generated.get("checks") if isinstance(generated, dict) else None
    has_zero_requirements = (
        requirements_path.is_file()
        and requirements_error == ""
        and isinstance(req_rows, list)
        and not req_rows
        and (
            not generated_path.is_file()
            or (
                generated_error == ""
                and isinstance(generated_checks, list)
                and not generated_checks
            )
        )
    )
    if has_zero_requirements:
        return skipped_gate(
            "live_topology",
            "Live topology checks",
            "Workspace live-topology proof requirements are explicitly empty.",
            details={
                "requirements_path": str(requirements_path),
                "generated_spec_path": str(generated_path),
                "requirements_count": 0,
                "generated_check_count": 0 if isinstance(generated_checks, list) else None,
            },
        )
    return artifact_presence_gate(
        workspace,
        "live_topology",
        "Live topology checks",
        "live_topology_checks.json",
        "LIVE_TOPOLOGY.md",
        row_keys=("rows", "checks", "results"),
        next_commands=[
            "python3 tools/engage.py --workspace <base_ws> --stage orient",
            "python3 tools/engage.py --workspace <base_ws> --stage live-checks",
            "make live-topology-proof-input-bridge WS=<base_ws> JSON=1",
            "make live-topology-proof-executor WS=<base_ws> JSON=1",
        ],
    )


def swival_gate(workspace: Path) -> dict[str, Any]:
    validation_path = workspace / ".auditooor" / "rust_corpus_validation.json"
    route_path = workspace / ".auditooor" / "rust_swival_route_evidence.json"
    validation, validation_error = load_json(validation_path)
    route, route_error = load_json(route_path)
    acceptance = validation.get("acceptance") if isinstance(validation, dict) else {}
    summary = validation.get("summary") if isinstance(validation, dict) else {}
    route_summary = route.get("summary") if isinstance(route, dict) else {}
    detectorization_unblocked = bool(isinstance(acceptance, dict) and acceptance.get("detectorization_unblocked"))
    found_total = int(summary.get("found_total") or 0) if isinstance(summary, dict) else 0
    expected_total = int(summary.get("expected_total") or 151) if isinstance(summary, dict) else 151
    route_rows = int(route_summary.get("row_count") or 0) if isinstance(route_summary, dict) else 0
    route_blockers = int(route_summary.get("blocker_count") or 0) if isinstance(route_summary, dict) else 0
    passed = (
        validation_path.is_file()
        and route_path.is_file()
        and not validation_error
        and not route_error
        and detectorization_unblocked
        and found_total >= expected_total
        and route_rows >= expected_total
        and route_blockers == 0
    )
    blockers: list[str] = []
    if not validation_path.is_file():
        blockers.append(".auditooor/rust_corpus_validation.json missing")
    if not route_path.is_file():
        blockers.append(".auditooor/rust_swival_route_evidence.json missing")
    if validation_error and validation_error != "missing":
        blockers.append(validation_error)
    if route_error and route_error != "missing":
        blockers.append(route_error)
    if not detectorization_unblocked:
        blockers.append("Swival rust-stdlib detectorization is not unblocked")
    if found_total < expected_total:
        blockers.append(f"Swival coverage incomplete: {found_total}/{expected_total}")
    if route_rows < expected_total:
        blockers.append(f"Swival route evidence incomplete: {route_rows}/{expected_total}")
    if route_blockers:
        blockers.append(f"Swival route evidence has {route_blockers} blockers")
    return gate(
        "swival_corpus",
        "Swival Rust stdlib corpus status",
        passed,
        details={
            "validation_path": str(validation_path),
            "route_path": str(route_path),
            "detectorization_unblocked": detectorization_unblocked,
            "found_total": found_total,
            "expected_total": expected_total,
            "route_rows": route_rows,
            "route_blockers": route_blockers,
        },
        blockers=blockers,
        next_commands=[
            "make rust-corpus-ingest WS=<base_ws> RUST_CORPUS_ROOT=<local_swival_rust_stdlib_checkout> JSON=1",
            "make rust-corpus-validate WS=<base_ws> STRICT=1 JSON=1",
            "make rust-swival-route-evidence WS=<base_ws> JSON=1",
        ],
    )


def zkbugs_gate(workspace: Path) -> dict[str, Any]:
    index_path = workspace / ".audit_logs" / "zkbugs_farming" / "zkbugs_index.json"
    queue_path = workspace / ".audit_logs" / "zkbugs_farming" / "provider_queue" / "zkbugs_provider_queue.json"
    last_pull_path = workspace / ".auditooor" / "zkbugs_last_pull"
    index, index_error = load_json(index_path)
    queue, queue_error = load_json(queue_path)
    index_summary = index.get("summary") if isinstance(index, dict) else {}
    if not isinstance(index_summary, dict):
        index_summary = {}
    total = int(index_summary.get("total") or index.get("total_records") or 0) if isinstance(index, dict) else 0
    queue_rows = 0
    if isinstance(queue, dict):
        for key in ("rows", "items", "queue"):
            if isinstance(queue.get(key), list):
                queue_rows = len(queue[key])
                break
    passed = index_path.is_file() and queue_path.is_file() and last_pull_path.is_file() and not index_error and not queue_error and total > 0 and queue_rows > 0
    blockers: list[str] = []
    if not index_path.is_file():
        blockers.append("zkBugs index missing")
    if not queue_path.is_file():
        blockers.append("zkBugs provider queue missing")
    if not last_pull_path.is_file():
        blockers.append("zkBugs last-pull marker missing")
    if index_error and index_error != "missing":
        blockers.append(index_error)
    if queue_error and queue_error != "missing":
        blockers.append(queue_error)
    if total <= 0:
        blockers.append("zkBugs index has zero records")
    if queue_rows <= 0:
        blockers.append("zkBugs provider queue has zero rows")
    return gate(
        "zkbugs_corpus",
        "zkBugs corpus status",
        passed,
        details={
            "index_path": str(index_path),
            "queue_path": str(queue_path),
            "last_pull_path": str(last_pull_path),
            "total_records": total,
            "provider_queue_rows": queue_rows,
        },
        blockers=blockers,
        next_commands=[
            "make zkbugs-pull ZKBUGS_ROOT=<local_zksecurity_zkbugs_checkout> DRY_RUN=1",
            "make zkbugs-pull ZKBUGS_ROOT=<local_zksecurity_zkbugs_checkout> LIVE=1 LIMIT=<n>",
            "make zkbugs-status",
        ],
    )


def runtime_dlt_gate(workspace: Path) -> dict[str, Any]:
    runtime_path = workspace / ".auditooor" / "rust_runtime_semantic_blockers.json"
    dlt_path = workspace / ".auditooor" / "runtime_dlt_execution_evidence_validator.json"
    runtime, runtime_error = load_json(runtime_path)
    dlt, dlt_error = load_json(dlt_path)
    dlt_rows = int(dlt.get("dlt_row_count") or len(dlt.get("rows") or [])) if isinstance(dlt, dict) else 0
    closure = int(dlt.get("closure_candidate_count") or 0) if isinstance(dlt, dict) else 0
    family_counts = runtime.get("runtime_component_family_counts") if isinstance(runtime, dict) else {}
    passed = runtime_path.is_file() and dlt_path.is_file() and not runtime_error and not dlt_error and bool(runtime) and bool(dlt) and dlt_rows > 0
    blockers: list[str] = []
    if not runtime_path.is_file():
        blockers.append("rust runtime semantic blockers artifact missing")
    if not dlt_path.is_file():
        blockers.append("runtime/DLT execution evidence validator artifact missing")
    if runtime_error and runtime_error != "missing":
        blockers.append(runtime_error)
    if dlt_error and dlt_error != "missing":
        blockers.append(dlt_error)
    if dlt_rows <= 0:
        blockers.append("runtime/DLT evidence has no rows")
    return gate(
        "runtime_dlt_evidence",
        "Runtime / DLT evidence",
        passed,
        details={
            "runtime_path": str(runtime_path),
            "dlt_path": str(dlt_path),
            "dlt_row_count": dlt_rows,
            "closure_candidate_count": closure,
            "runtime_component_family_counts": family_counts if isinstance(family_counts, dict) else {},
        },
        blockers=blockers,
        next_commands=[
            "make rust-runtime-semantic-blockers WS=<base_ws> JSON=1",
            "make runtime-dlt-execution-evidence WS=<base_ws> JSON=1",
            "make rust-base-readiness WS=<base_ws> JSON=1",
        ],
    )


def ordered_next_commands(gates: Sequence[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    commands: list[str] = []
    for item in gates:
        if item["status"] == "PASS":
            continue
        for command in item["next_commands"]:
            if command not in seen:
                seen.add(command)
                commands.append(command)
    if not commands:
        commands = [
            "python3 tools/engage.py --workspace <base_ws> --stages intake-baseline,orient,live-checks,env-check,scan-rust,mine-prioritize --summary",
            "make rust-base-readiness WS=<base_ws> JSON=1",
            "make critical-hunt WS=<base_ws>",
        ]
    return commands


def build_payload(
    workspace: Path,
    *,
    smart_contract_roots: Sequence[Path] | None = None,
    rust_dlt_roots: Sequence[Path] | None = None,
) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    context = asset_context(workspace, smart_contract_roots or [], rust_dlt_roots or [])
    gates = [
        scope_gate(workspace, context),
        project_source_gate(workspace, smart_contract_roots or [], rust_dlt_roots or [], context),
        scan_rust_gate(workspace)
        if context.needs_rust_dlt
        else skipped_gate(
            "scan_rust_summary",
            "Rust/DLT scan-rust summary",
            "Rust/DLT assets are not indicated by intake, scope, or declared source roots.",
            details={"asset_context": asset_context_details(context)},
        ),
        semantic_graph_gate(workspace),
        live_topology_gate(workspace),
        swival_gate(workspace)
        if context.needs_rust_dlt
        else skipped_gate(
            "swival_corpus",
            "Swival Rust stdlib corpus status",
            "Rust/DLT assets are not indicated by intake, scope, or declared source roots.",
            details={"asset_context": asset_context_details(context)},
        ),
        zkbugs_gate(workspace)
        if context.needs_zk
        else skipped_gate(
            "zkbugs_corpus",
            "zkBugs corpus status",
            "zk assets are not indicated by intake or scope.",
            details={"asset_context": asset_context_details(context)},
        ),
        runtime_dlt_gate(workspace)
        if context.needs_rust_dlt
        else skipped_gate(
            "runtime_dlt_evidence",
            "Runtime / DLT evidence",
            "Rust/DLT assets are not indicated by intake, scope, or declared source roots.",
            details={"asset_context": asset_context_details(context)},
        ),
    ]
    blocked = [item for item in gates if item["status"] == "BLOCKED"]
    status = "PASS" if not blocked else "BLOCKED"
    blockers = [blocker for item in blocked for blocker in item["blockers"]]
    return {
        "schema": SCHEMA,
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "status": status,
        "can_start_base_scan": status == "PASS",
        "ready_for_submission_or_proof_promotion": False,
        "gate_counts": dict(sorted(Counter(item["status"] for item in gates).items())),
        "blocker_count": len(blockers),
        "blockers": blockers,
        "gates": gates,
        "asset_context": asset_context_details(context),
        "next_commands": ordered_next_commands(gates),
        "proof_boundary": "Preflight readiness only. PASS does not prove exploit impact, production reachability, severity, OOS clearance for a finding, or submission readiness.",
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Base Scan Preflight",
        "",
        f"- Status: `{payload['status']}`",
        f"- Can start Base scan: `{payload['can_start_base_scan']}`",
        f"- Blockers: `{payload['blocker_count']}`",
        "",
        "## Gates",
        "",
        "| Gate | Status | Blockers |",
        "|---|---|---|",
    ]
    for item in payload["gates"]:
        blockers = "<br>".join(item["blockers"]) if item["blockers"] else "none"
        lines.append(f"| `{item['id']}` | `{item['status']}` | {blockers} |")
    lines.extend(["", "## Next Commands", ""])
    for idx, command in enumerate(payload["next_commands"], start=1):
        lines.append(f"{idx}. `{command}`")
    lines.extend(["", "## Gate Details", ""])
    for item in payload["gates"]:
        lines.extend([f"### {item['title']}", "", f"- Status: `{item['status']}`"])
        for key, value in item["details"].items():
            if isinstance(value, (str, int, bool)):
                lines.append(f"- `{key}`: `{value}`")
        if item["blockers"]:
            lines.append("- Blockers: " + "; ".join(item["blockers"]))
        lines.append("")
    lines.extend(["## Boundary", "", payload["proof_boundary"], ""])
    return "\n".join(lines)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--smart-contract-root", action="append", type=Path, default=[])
    parser.add_argument("--rust-dlt-root", action="append", type=Path, default=[])
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    payload = build_payload(
        workspace,
        smart_contract_roots=args.smart_contract_root,
        rust_dlt_roots=args.rust_dlt_root,
    )
    out_json = args.out_json or workspace / DEFAULT_OUT_JSON
    out_md = args.out_md or workspace / DEFAULT_OUT_MD
    write_json(out_json, payload)
    write_text(out_md, render_markdown(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
