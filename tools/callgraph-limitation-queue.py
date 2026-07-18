#!/usr/bin/env python3
"""Queue closure tasks for detector-lint inter-contract callgraph blockers.

`detector-lint --fail-inter-contract-claim-without-callgraph` intentionally
only tells us which detectors make an inter-contract claim without reading a
Slither callgraph API. This tool turns that lint cohort into an operator queue:
each blocker fans out into exact callgraph rewrite, semantic graph input,
fixture, claim-scope audit, and terminal non-detectorizable decision tasks.

The output is advisory bookkeeping only. It never proves impact, assigns
severity, runs detectors, or marks a row promotion-ready.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
LINT_PATH = ROOT / "tools" / "detector-lint.py"
SCHEMA_VERSION = "auditooor.callgraph_limitation_queue.v1"
SOURCE_SHAPE_LIMITATIONS = [
    "detector-lint claim matching is heuristic and prose-driven",
    "no compiler-backed callgraph fixpoint is proven by this queue",
    "semantic graph tasks are source-shape inputs only",
    "fixture tasks are requirements, not executed smoke-fire proof",
    "no severity, selected impact, PoC posture, or submission readiness may be inferred",
]


def _load_lint_module() -> Any:
    spec = importlib.util.spec_from_file_location("detector_lint_for_callgraph_queue", LINT_PATH)
    if not spec or not spec.loader:
        raise SystemExit(f"[callgraph-limitation-queue] cannot import {LINT_PATH}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _slug(value: str, fallback: str = "unknown") -> str:
    out = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return out or fallback


def _safe_rel(path: Path, root: Path = ROOT) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _first_match(pattern: str, text: str) -> str:
    match = re.search(pattern, text, re.I | re.M)
    return match.group(1).strip() if match else ""


def _generated_dsl_path(src: str) -> str:
    candidate = _first_match(r"Regenerate via:\s*python3\s+tools/pattern-compile\.py\s+([^\s#]+)", src)
    if not candidate:
        return ""
    path = ROOT / "reference" / "patterns.dsl" / candidate
    return _safe_rel(path) if path.exists() else f"reference/patterns.dsl/{candidate}"


def _fixture_dir(detector_path: Path) -> str:
    stem = detector_path.stem
    candidates = [
        ROOT / "detectors" / "_fixtures" / stem,
        ROOT / "detectors" / "fixtures" / stem,
        ROOT / "detectors" / "test_fixtures" / stem,
    ]
    for candidate in candidates:
        if candidate.exists():
            return _safe_rel(candidate)
    return f"detectors/_fixtures/{stem}"


def _family(path: Path, labels: list[str], src: str) -> str:
    haystack = f"{path.stem} {' '.join(labels)} {src[:2500]}".lower()
    if "proxy" in haystack or "implementation" in haystack or "uups" in haystack or "beacon" in haystack:
        return "proxy_or_upgrade_callgraph"
    if "factory" in haystack or "create2" in haystack or "clone" in haystack or "create3" in haystack:
        return "factory_deployment_callgraph"
    if "read-only" in haystack or "reentr" in haystack or "callback" in haystack:
        return "cross_function_or_readonly_reentrancy_callgraph"
    if "chain" in haystack or "state" in haystack or "ccip" in haystack or "wormhole" in haystack:
        return "cross_chain_peer_callgraph"
    if "oracle" in haystack or "verifier" in haystack or "signature" in haystack:
        return "oracle_or_verifier_relation_callgraph"
    if "sibling" in haystack:
        return "sibling_path_callgraph"
    return "generic_inter_contract_callgraph"


def _callgraph_api_hints(family: str) -> list[str]:
    if family == "proxy_or_upgrade_callgraph":
        return ["function.high_level_calls", "function.low_level_calls", "delegatecall/calls_as_expressions", "compilation_unit.contracts"]
    if family == "factory_deployment_callgraph":
        return ["function.high_level_calls", "new/clone/create call expression walk", "compilation_unit.contracts"]
    if family == "cross_function_or_readonly_reentrancy_callgraph":
        return ["function.high_level_calls", "function.internal_calls", "function.reaches_external", "function.has_high_level_call_named"]
    if family == "cross_chain_peer_callgraph":
        return ["contract.has_external_call_to", "function.high_level_calls", "typed receiver relation edge"]
    if family == "oracle_or_verifier_relation_callgraph":
        return ["function.has_high_level_call_named", "function.high_level_calls", "semantic_graph relation_edges"]
    return ["function.high_level_calls", "function.internal_calls", "compilation_unit.contracts"]


def _common_task(
    *,
    blocker: dict[str, Any],
    task_id: str,
    task_kind: str,
    action_lane: str,
    required_artifacts: list[str],
    recommended_action: str,
    terminal_decision: list[str],
) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "blocker_id": blocker["blocker_id"],
        "detector_path": blocker["detector_path"],
        "detector_argument": blocker["detector_argument"],
        "candidate_family": blocker["candidate_family"],
        "claim_labels": blocker["claim_labels"],
        "task_kind": task_kind,
        "action_lane": action_lane,
        "task_status": "open_advisory",
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_status": "NOT_SUBMIT_READY",
        "severity": "none",
        "selected_impact": "",
        "impact_contract_required": True,
        "promotion_allowed": False,
        "advisory_only": True,
        "required_artifacts": required_artifacts,
        "recommended_action": recommended_action,
        "terminal_decision_options": terminal_decision,
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
    }


def _tasks_for_blocker(blocker: dict[str, Any], index: int) -> list[dict[str, Any]]:
    base = f"CGL-{index:03d}"
    family = blocker["candidate_family"]
    fixture = blocker["expected_fixture_dir"]
    dsl = blocker.get("dsl_source_path") or "no generated DSL source detected"
    callgraph_hints = _callgraph_api_hints(family)
    return [
        _common_task(
            blocker=blocker,
            task_id=f"{base}-CALLGRAPH",
            task_kind="callgraph_required_detector_rewrite",
            action_lane="callgraph_required",
            required_artifacts=[
                f"detector diff in {blocker['detector_path']}",
                "one Slither callgraph/predicate-engine key that matches the claim",
                f"preferred APIs: {', '.join(callgraph_hints)}",
                "detector-lint --fail-inter-contract-claim-without-callgraph clean for this detector",
            ],
            recommended_action=(
                "Rewrite the detector so its executable predicate follows the claimed "
                "caller/callee/deployment relationship instead of relying on single-function prose."
            ),
            terminal_decision=[
                "callgraph_rewrite_landed_with_fixture_pair",
                "semantic_graph_input_required_before_rewrite",
                "non_detectorizable_claim_reword_or_retire",
            ],
        ),
        _common_task(
            blocker=blocker,
            task_id=f"{base}-SEMANTIC",
            task_kind="semantic_graph_input_task",
            action_lane="semantic_graph_required",
            required_artifacts=[
                "semantic_graph relation_edges or multi_hop_paths row for the claimed relation",
                "semantic-detector-worklist row or semantic_graph_query spec for the relation",
                "source component, target component, method, file, line, and evidence fields",
                "record if no stable source-shape query can represent the claim",
            ],
            recommended_action=(
                "Model the claimed inter-contract edge as semantic graph input before "
                "deciding whether a detector predicate is feasible."
            ),
            terminal_decision=[
                "semantic_graph_query_spec_added",
                "semantic_graph_source_shape_missing",
                "terminal_source_review_only",
            ],
        ),
        _common_task(
            blocker=blocker,
            task_id=f"{base}-FIXTURE",
            task_kind="paired_fixture_requirement",
            action_lane="fixture_pair_required",
            required_artifacts=[
                f"positive fixture under {fixture}",
                f"clean fixture under {fixture}",
                "fixture asserts the cross-contract/cross-function edge, not only local syntax",
                "detector smoke output proving positive fires and clean stays quiet",
            ],
            recommended_action=(
                "Add or locate a paired fixture that forces the claimed relationship to "
                "exist mechanically, then use it to constrain the detector rewrite."
            ),
            terminal_decision=[
                "fixture_pair_landed_and_smoked",
                "fixture_impossible_without_runtime_harness",
                "terminal_non_detectorizable_no_fixture",
            ],
        ),
        _common_task(
            blocker=blocker,
            task_id=f"{base}-CLAIM",
            task_kind="claim_scope_audit",
            action_lane="claim_scope_required",
            required_artifacts=[
                "module docstring / HELP / WIKI claim reviewed against executable predicate",
                f"DSL source reviewed: {dsl}",
                "claim either narrowed to local syntax or backed by callgraph evidence",
                "false-positive prose trigger documented if detector is already local-only",
            ],
            recommended_action=(
                "Audit whether detector prose over-claims inter-contract coverage. If the "
                "pattern is intentionally local, narrow wording instead of adding fake callgraph reads."
            ),
            terminal_decision=[
                "claim_reworded_to_local_detector",
                "claim_confirmed_callgraph_required",
                "detector_retired_or_reframed_source_review_only",
            ],
        ),
        _common_task(
            blocker=blocker,
            task_id=f"{base}-TERMINAL",
            task_kind="terminal_non_detectorizable_decision",
            action_lane="terminal_decision_required",
            required_artifacts=[
                "one explicit terminal state recorded for the blocker",
                "reason why the detector can or cannot be mechanically checked",
                "next command for detector rewrite, semantic graph input, or retirement",
                "no report/harness/severity promotion until terminal state is detector-backed",
            ],
            recommended_action=(
                "Close the lint blocker with a durable terminal decision rather than "
                "leaving it as an unstructured prose limitation."
            ),
            terminal_decision=[
                "detectorizable_callgraph_required",
                "semantic_graph_input_required",
                "fixture_first_before_detector",
                "terminal_non_detectorizable_source_review_only",
            ],
        ),
    ]


def _blocker_rows(folders: Iterable[Path] | None = None) -> list[dict[str, Any]]:
    lint = _load_lint_module()
    folder_args = [folder.resolve() for folder in folders] if folders else None
    hits = lint.inter_contract_claim_without_callgraph(folders=folder_args)
    rows: list[dict[str, Any]] = []
    for idx, (path, labels, _count) in enumerate(hits, start=1):
        src = _read(path)
        argument = _first_match(r"ARGUMENT\s*=\s*[\"']([^\"']+)[\"']", src) or path.stem.replace("_", "-")
        labels_list = [str(label) for label in labels]
        family = _family(path, labels_list, src)
        rows.append(
            {
                "blocker_id": f"CGL-BLOCKER-{idx:03d}",
                "detector_path": _safe_rel(path),
                "detector_argument": argument,
                "claim_labels": labels_list,
                "candidate_family": family,
                "dsl_source_path": _generated_dsl_path(src),
                "expected_fixture_dir": _fixture_dir(path),
                "callgraph_api_hints": _callgraph_api_hints(family),
                "source_excerpt": " ".join(src.split())[:360],
                "terminal_state": "open_advisory",
                "promotion_allowed": False,
                "submission_posture": "NOT_SUBMIT_READY",
            }
        )
    return rows


def build_queue(*, folders: Iterable[Path] | None = None, limit: int = 300) -> dict[str, Any]:
    blockers = _blocker_rows(folders=folders)
    tasks: list[dict[str, Any]] = []
    for idx, blocker in enumerate(blockers, start=1):
        for task in _tasks_for_blocker(blocker, idx):
            if len(tasks) >= limit:
                break
            tasks.append(task)
        if len(tasks) >= limit:
            break
    lane_counts: dict[str, int] = {}
    family_counts: dict[str, int] = {}
    for task in tasks:
        lane = str(task.get("action_lane") or "unknown")
        lane_counts[lane] = lane_counts.get(lane, 0) + 1
        family = str(task.get("candidate_family") or "unknown")
        family_counts[family] = family_counts.get(family, 0) + 1
    return {
        "schema": SCHEMA_VERSION,
        "source_lint_flag": "detector-lint --fail-inter-contract-claim-without-callgraph",
        "coverage_claim": "none_advisory_queue_only",
        "advisory_only": True,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "blocker_count": len(blockers),
        "task_count": len(tasks),
        "limit": limit,
        "target_task_range": "150-300",
        "action_lane_counts": lane_counts,
        "candidate_family_counts": family_counts,
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
        "mechanical_path": [
            "detector-lint inter-contract claim/no-callgraph blocker",
            "callgraph limitation queue exact task fan-out",
            "semantic graph input or callgraph rewrite decision",
            "paired fixtures and detector smoke before promotion",
            "terminal non-detectorizable/source-review-only decision if no static predicate exists",
        ],
        "blockers": blockers,
        "tasks": tasks,
        "next_actions": [
            "Pick a blocker and complete its CALLGRAPH, SEMANTIC, FIXTURE, CLAIM, or TERMINAL task.",
            "Re-run detector-lint with the fail flag after each detector rewrite or claim reword.",
            "Do not promote any row without fixture smoke output and exact impact proof.",
        ],
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Callgraph Limitation Queue",
        "",
        "Advisory closure queue for detectors that claim inter-contract semantics without callgraph evidence.",
        "Rows are not findings, not severity approvals, and not promotion-ready.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- source lint flag: `{payload['source_lint_flag']}`",
        f"- blockers: {payload['blocker_count']}",
        f"- tasks: {payload['task_count']}",
        f"- promotion allowed: `{str(payload['promotion_allowed']).lower()}`",
        f"- posture: `{payload['submission_posture']}`",
        "",
        "## Source-Shape Limitations",
        "",
    ]
    for limitation in payload.get("source_shape_limitations", []):
        lines.append(f"- {limitation}")
    lines.extend(["", "## Blockers", ""])
    blockers = payload.get("blockers") if isinstance(payload.get("blockers"), list) else []
    lines.append("| Blocker | Detector | Family | Claims | Expected Fixture |")
    lines.append("|---|---|---|---|---|")
    for blocker in blockers:
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                blocker.get("blocker_id", ""),
                blocker.get("detector_path", ""),
                blocker.get("candidate_family", ""),
                ", ".join(blocker.get("claim_labels") or []),
                blocker.get("expected_fixture_dir", ""),
            )
        )
    lines.extend(["", "## Tasks", ""])
    tasks = payload.get("tasks") if isinstance(payload.get("tasks"), list) else []
    if not tasks:
        lines.append("_No callgraph limitation tasks were generated._")
        return "\n".join(lines) + "\n"
    lines.append("| Task | Lane | Detector | Required Artifacts | Terminal Decisions |")
    lines.append("|---|---|---|---|---|")
    for task in tasks:
        lines.append(
            "| `{}` | `{}` | `{}` | {} | `{}` |".format(
                task.get("task_id", ""),
                task.get("action_lane", ""),
                task.get("detector_path", ""),
                "<br>".join(task.get("required_artifacts") or []),
                "`, `".join(task.get("terminal_decision_options") or []),
            )
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-json", type=Path, default=ROOT / ".auditooor" / "callgraph_limitation_queue.json")
    parser.add_argument("--out-md", type=Path, default=ROOT / ".auditooor" / "callgraph_limitation_queue.md")
    parser.add_argument("--limit", type=int, default=300)
    parser.add_argument(
        "--detector-folder",
        action="append",
        type=Path,
        help="Override detector folders to scan. Primarily used by focused tests.",
    )
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    folders = [folder.expanduser().resolve() for folder in args.detector_folder or []]
    payload = build_queue(folders=folders or None, limit=max(0, args.limit))
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[callgraph-limitation-queue] OK "
        f"blockers={payload['blocker_count']} tasks={payload['task_count']} json={args.out_json}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
