#!/usr/bin/env python3
"""Build planning-only Foundry v1.7 config-normalization execution packets.

This consumes generated v1.7 trial manifests and config-normalization queues.
It deliberately does not install Foundry, upgrade Foundry, run Forge, or edit
workspace foundry.toml files. Patch content is emitted as operator-reviewed
suggestions only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.foundry_v1_7_normalization_plan.v1"
DEFAULT_OUT_DIR = Path(".audit_logs/pr560_worker_as/foundry_v1_7_config_normalization")
DEFAULT_SEED = "0x56017"
MANIFEST_NAME = "foundry_v1_7_trial_manifest.json"
QUEUE_NAME = "foundry_v1_7_config_normalization_queue.json"


RISK_CATALOG: dict[str, dict[str, Any]] = {
    "missing_explicit_hardfork": {
        "risk_category": "fork_default_drift",
        "priority": "P0",
        "patch_theme": "Pin proof runs to an explicit EVM/hardfork before comparing v1.5.x and v1.7.1.",
        "expected_breakage_classes": [
            "hardfork_or_network_default_delta",
            "opcode_or_precompile_semantic_delta",
            "gas_schedule_or_default_evm_delta",
        ],
        "blocks": ["baseline_vs_target_interpretation", "final_submission_proof"],
    },
    "missing_network_key": {
        "risk_category": "network_context_ambiguity",
        "priority": "P1",
        "patch_theme": "Record the intended network context or a source-only waiver for non-fork fixtures.",
        "expected_breakage_classes": [
            "hardfork_or_network_default_delta",
            "wrong_chain_rpc_assumption",
            "per_network_config_shadowing",
        ],
        "blocks": ["live_or_fork_claims"],
    },
    "missing_fuzz_seed": {
        "risk_category": "nondeterministic_fuzz_evidence",
        "priority": "P0",
        "patch_theme": "Make proof-quality fuzz and invariant replay deterministic with an explicit seed.",
        "expected_breakage_classes": [
            "random_seed_or_parallelism_delta",
            "counterexample_not_replayable",
            "parallel_fuzz_order_delta",
        ],
        "blocks": ["final_fuzz_or_invariant_proof", "poc_execution_replayability"],
    },
    "missing_repro_profiles": {
        "risk_category": "missing_proof_profiles",
        "priority": "P1",
        "patch_theme": "Add proof-quality invariant/fuzz replay profiles before using v1.7 campaign evidence.",
        "expected_breakage_classes": [
            "profile_not_found",
            "check_interval_profile_confusion",
            "exploratory_run_used_as_final_proof",
        ],
        "blocks": ["operator_closeout_confidence"],
    },
    "check_interval_exploratory_only": {
        "risk_category": "exploratory_interval_unsound_for_final_proof",
        "priority": "P0",
        "patch_theme": "Keep interval checking out of final proof profiles unless a proof explains why it is safe.",
        "expected_breakage_classes": [
            "transient_invariant_missed",
            "exploratory_run_used_as_final_proof",
        ],
        "blocks": ["final_invariant_proof"],
    },
    "no_foundry_toml_detected": {
        "risk_category": "missing_forge_project_root",
        "priority": "P0",
        "patch_theme": "Identify the Forge root before planning a v1.7 comparison.",
        "expected_breakage_classes": [
            "environment_or_remapping_issue",
            "forge_root_not_found",
        ],
        "blocks": ["all_foundry_trial_execution"],
    },
}


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _slug(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower()
    return slug or "workspace"


def _workspace_id(workspace: Path, root: Path) -> str:
    return _slug(_rel(workspace, root))


def discover_workspace_inputs(root: Path) -> list[dict[str, Path]]:
    manifests = sorted(path for path in root.rglob(MANIFEST_NAME) if ".git" not in path.parts)
    rows: list[dict[str, Path]] = []
    for manifest in manifests:
        auditooor_dir = manifest.parent
        queue = auditooor_dir / QUEUE_NAME
        if not queue.is_file():
            continue
        rows.append({"workspace": auditooor_dir.parent, "manifest": manifest, "queue": queue})
    return rows


def _suggested_patch_for_warning(code: str, config_path: str, seed: str) -> str:
    header = f"--- a/{config_path}\n+++ b/{config_path}\n"
    if code == "missing_explicit_hardfork":
        return header + "@@ [profile.default]\n+# Suggested only; choose the chain-specific value before applying.\n+evm_version = \"cancun\"\n"
    if code == "missing_network_key":
        return header + "@@ [profile.default]\n+# Suggested only; replace with the workspace's actual target network or waive source-only fixtures.\n+network = \"local\"\n"
    if code == "missing_fuzz_seed":
        return header + f"@@ [profile.default]\n+# Suggested only; keep this seed in validation logs and execution manifests.\n+seed = \"{seed}\"\n"
    if code == "missing_repro_profiles":
        return (
            header
            + "@@\n+[profile.invariants]\n"
            + f"+seed = \"{seed}\"\n"
            + "+check_interval = 1\n+\n"
            + "+[profile.fuzz_repro]\n"
            + f"+seed = \"{seed}\"\n"
            + "+fail_on_revert = true\n"
        )
    if code == "check_interval_exploratory_only":
        return header + "@@ [profile.invariants]\n+# Suggested only; final proof profiles should omit check_interval or set it to 1.\n+check_interval = 1\n"
    if code == "no_foundry_toml_detected":
        return "--- /dev/null\n+++ b/foundry.toml\n@@\n+# Suggested only; first confirm the actual Forge project root.\n+[profile.default]\n+src = \"src\"\n+test = \"test\"\n"
    return header + "@@\n+# Suggested only; manually normalize this config warning before execution.\n"


def build_patch_suggestion(workspace_id: str, index: int, item: dict[str, Any], seed: str) -> dict[str, Any]:
    code = str(item.get("source_warning_code") or "unknown_warning")
    risk = RISK_CATALOG.get(code, {
        "risk_category": "unknown_config_risk",
        "priority": "P2",
        "patch_theme": "Manual review required before execution.",
        "expected_breakage_classes": ["unknown_needs_manual_triage"],
        "blocks": ["classification"],
    })
    config_path = str(item.get("path") or "foundry.toml")
    return {
        "id": f"AS-FN17-{workspace_id}-{index:03d}",
        "queue_item_id": item.get("id"),
        "source_warning_code": code,
        "status": "suggested_not_applied",
        "migration_state": "planned_not_executed",
        "config_path": config_path,
        "risk_category": risk["risk_category"],
        "priority": risk["priority"],
        "blocks_final_proof": bool(item.get("blocks_final_proof")),
        "patch_theme": risk["patch_theme"],
        "operator_decision_required": True,
        "suggested_patch": _suggested_patch_for_warning(code, config_path, seed),
        "expected_breakage_classes": risk["expected_breakage_classes"],
        "blocked_evidence_roles": risk["blocks"],
        "source_action": item.get("action", ""),
        "source_reason": item.get("reason", ""),
    }


def _validation_commands(workspace: Path, seed: str) -> list[dict[str, Any]]:
    ws = str(workspace)
    target_prefix = "PATH=<isolated-foundry-v1.7.1-bin>:$PATH"
    rows = [
        ("baseline-version-inventory", f"python3 tools/foundry-version-report.py --workspace {ws} --print-json", "environment_provenance_only", True),
        ("baseline-forge-build", f"forge --root {ws} build", "comparison_baseline", True),
        ("baseline-forge-test-seeded", f"forge --root {ws} test --fuzz-seed {seed}", "comparison_baseline", True),
        ("baseline-invariant-proof-profile", f"FOUNDRY_PROFILE=invariants forge --root {ws} test --fuzz-seed {seed}", "comparison_baseline", False),
        ("target-version-inventory", f"{target_prefix} python3 tools/foundry-version-report.py --workspace {ws} --print-json", "environment_provenance_only", True),
        ("target-forge-build", f"{target_prefix} forge --root {ws} build", "trial_comparison_only", True),
        ("target-forge-test-seeded", f"{target_prefix} forge --root {ws} test --fuzz-seed {seed}", "trial_comparison_only", True),
        ("target-invariant-proof-profile", f"{target_prefix} FOUNDRY_PROFILE=invariants forge --root {ws} test --fuzz-seed {seed}", "trial_comparison_only", False),
        ("target-invariant-fast-exploratory", f"{target_prefix} FOUNDRY_PROFILE=invariants_fast forge --root {ws} test --fuzz-seed {seed}", "exploratory_only_not_submission_proof", False),
        ("post-trial-poc-execution-record", f"python3 tools/poc-execution-record.py --workspace {ws} --brief <brief.md> --run '<approved target forge command>' --final-result needs_human --impact-assertion unknown", "execution_manifest_if_operator_approved", False),
    ]
    return [
        {
            "id": command_id,
            "command": command,
            "proof_role": proof_role,
            "required": required,
            "status": "planned_not_executed",
        }
        for command_id, command, proof_role, required in rows
    ]


def build_workspace_plan(row: dict[str, Path], root: Path, seed: str) -> dict[str, Any]:
    manifest = _load_json(row["manifest"])
    queue = _load_json(row["queue"])
    workspace = row["workspace"].resolve()
    workspace_id = _workspace_id(workspace, root)
    items = queue.get("items") or []
    suggestions = [build_patch_suggestion(workspace_id, idx + 1, item, seed) for idx, item in enumerate(items)]
    exact_remaining_blockers = [
        {
            "id": f"AS-FN17-BLOCKER-{suggestion['id']}",
            "workspace_id": workspace_id,
            "source_warning_code": suggestion["source_warning_code"],
            "risk_category": suggestion["risk_category"],
            "priority": suggestion["priority"],
            "blocks": suggestion["blocked_evidence_roles"],
            "status": "blocked_until_operator_decision",
            "next_action": suggestion["source_action"],
        }
        for suggestion in suggestions
        if suggestion.get("blocks_final_proof")
    ]
    exact_remaining_blockers.append(
        {
            "id": f"AS-FN17-BLOCKER-{workspace_id}-ISOLATED-TRIAL",
            "workspace_id": workspace_id,
            "source_warning_code": "isolated_trial_not_executed",
            "risk_category": "target_execution_absent",
            "priority": "P0",
            "blocks": ["v1_7_compatibility_claim", "final_migration_closeout"],
            "status": "blocked_until_operator_approved_isolated_trial",
            "next_action": "Run the paired baseline/target commands only after the operator approves an isolated v1.7.1 PATH.",
        }
    )
    risk_counts: dict[str, int] = {}
    priority_counts: dict[str, int] = {}
    breakage_counts: dict[str, int] = {}
    for suggestion in suggestions:
        risk_counts[suggestion["risk_category"]] = risk_counts.get(suggestion["risk_category"], 0) + 1
        priority_counts[suggestion["priority"]] = priority_counts.get(suggestion["priority"], 0) + 1
        for klass in suggestion["expected_breakage_classes"]:
            breakage_counts[klass] = breakage_counts.get(klass, 0) + 1
    commands = _validation_commands(workspace, seed)
    return {
        "workspace_id": workspace_id,
        "workspace": str(workspace),
        "manifest_path": _rel(row["manifest"], root),
        "queue_path": _rel(row["queue"], root),
        "migration_state": "planned_not_executed",
        "upgrade_performed": False,
        "fixture_config_edits_allowed": False,
        "manifest_readiness_status": manifest.get("readiness_accounting", {}).get("status", "unknown"),
        "queue_item_count": queue.get("item_count", len(items)),
        "blocking_queue_item_count": queue.get("blocking_item_count", 0),
        "patch_suggestions": suggestions,
        "exact_remaining_blockers": exact_remaining_blockers,
        "risk_counts": risk_counts,
        "priority_counts": priority_counts,
        "expected_breakage_counts": breakage_counts,
        "validation_commands": commands,
        "closeout_requirements": [
            "Operator reviews suggested patches before any foundry.toml edit.",
            "Baseline and target commands are paired by command id.",
            "Every delta is assigned an expected_breakage class before promotion.",
            "Final fuzz/invariant evidence records seed, profile, hardfork/EVM, network, and Foundry version.",
            "Any check_interval > 1 result remains exploratory unless justified in the final proof.",
        ],
    }


def build_plan(root: Path, workspace_rows: list[dict[str, Path]], seed: str) -> dict[str, Any]:
    workspaces = [build_workspace_plan(row, root, seed) for row in workspace_rows]
    aggregate_risk_counts: dict[str, int] = {}
    aggregate_breakage_counts: dict[str, int] = {}
    for workspace in workspaces:
        for key, value in workspace["risk_counts"].items():
            aggregate_risk_counts[key] = aggregate_risk_counts.get(key, 0) + value
        for key, value in workspace["expected_breakage_counts"].items():
            aggregate_breakage_counts[key] = aggregate_breakage_counts.get(key, 0) + value
    total_queue_items = sum(int(ws["queue_item_count"]) for ws in workspaces)
    total_blocking = sum(int(ws["blocking_queue_item_count"]) for ws in workspaces)
    total_suggestions = sum(len(ws["patch_suggestions"]) for ws in workspaces)
    total_commands = sum(len(ws["validation_commands"]) for ws in workspaces)
    exact_remaining_blockers = [
        blocker
        for workspace in workspaces
        for blocker in workspace.get("exact_remaining_blockers", [])
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_unix": int(time.time()),
        "root": str(root),
        "status": "planned_not_executed",
        "upgrade_performed": False,
        "install_or_upgrade_allowed": False,
        "seed": seed,
        "input_manifest_count": len(workspace_rows),
        "input_queue_count": len(workspace_rows),
        "workspace_count": len(workspaces),
        "queue_item_count": total_queue_items,
        "blocking_queue_item_count": total_blocking,
        "patch_suggestion_count": total_suggestions,
        "validation_command_count": total_commands,
        "concrete_planning_item_count": total_suggestions + total_commands,
        "exact_remaining_blocker_count": len(exact_remaining_blockers),
        "exact_remaining_blockers": exact_remaining_blockers,
        "risk_counts": aggregate_risk_counts,
        "expected_breakage_counts": aggregate_breakage_counts,
        "progress_accounting": {
            "queues_consumed": len(workspace_rows),
            "queue_items_consumed": total_queue_items,
            "patches_applied": 0,
            "forge_commands_executed": 0,
            "target_trials_executed": 0,
            "remaining_operator_patch_decisions": total_suggestions,
            "remaining_blocking_items": total_blocking,
            "remaining_exact_blockers": len(exact_remaining_blockers),
            "closeout_status": "blocked_until_operator_reviews_suggestions_and_runs_isolated_trial",
        },
        "proof_boundary": "Planning artifacts only; not installation evidence, execution evidence, config edits, or exploit proof.",
        "workspaces": workspaces,
    }


def render_markdown(plan: dict[str, Any]) -> str:
    lines = [
        "# Foundry v1.7.1 Config Normalization Execution Plan",
        "",
        "Status: `planned_not_executed`; no install, upgrade, Forge run, GitHub action, or fixture config edit was performed.",
        "",
        "## Closeout Accounting",
        "",
        f"- workspaces: `{plan['workspace_count']}`",
        f"- queues consumed: `{plan['input_queue_count']}`",
        f"- queue items consumed: `{plan['queue_item_count']}`",
        f"- blocking queue items: `{plan['blocking_queue_item_count']}`",
        f"- patch suggestions: `{plan['patch_suggestion_count']}`",
        f"- validation commands planned: `{plan['validation_command_count']}`",
        f"- concrete planning items: `{plan['concrete_planning_item_count']}`",
        f"- exact remaining blockers: `{plan['exact_remaining_blocker_count']}`",
        f"- patches applied: `{plan['progress_accounting']['patches_applied']}`",
        f"- forge commands executed: `{plan['progress_accounting']['forge_commands_executed']}`",
        "",
        "## Exact Remaining Blockers",
        "",
    ]
    for blocker in plan.get("exact_remaining_blockers", []):
        lines.append(
            f"- `{blocker['id']}` ({blocker['priority']}, `{blocker['risk_category']}`): {blocker['next_action']}"
        )
    if not plan.get("exact_remaining_blockers"):
        lines.append("- none")
    lines.extend([
        "",
        "## Risk Categories",
        "",
    ])
    for risk, count in sorted(plan.get("risk_counts", {}).items()):
        lines.append(f"- `{risk}`: `{count}`")
    lines.extend(["", "## Expected Breakage Classes", ""])
    for klass, count in sorted(plan.get("expected_breakage_counts", {}).items()):
        lines.append(f"- `{klass}`: `{count}`")
    for workspace in plan["workspaces"]:
        lines.extend([
            "",
            f"## Workspace `{workspace['workspace_id']}`",
            "",
            f"- path: `{workspace['workspace']}`",
            f"- readiness: `{workspace['manifest_readiness_status']}`",
            f"- queue: `{workspace['queue_path']}`",
            f"- patch suggestions: `{len(workspace['patch_suggestions'])}`",
            f"- validation commands: `{len(workspace['validation_commands'])}`",
            f"- exact remaining blockers: `{len(workspace['exact_remaining_blockers'])}`",
            "",
            "### Patch Suggestions",
            "",
        ])
        for suggestion in workspace["patch_suggestions"]:
            lines.extend([
                f"#### {suggestion['id']}",
                "",
                f"- queue item: `{suggestion['queue_item_id']}`",
                f"- warning: `{suggestion['source_warning_code']}`",
                f"- risk: `{suggestion['risk_category']}`",
                f"- priority: `{suggestion['priority']}`",
                f"- status: `{suggestion['status']}`",
                f"- breakage classes: `{', '.join(suggestion['expected_breakage_classes'])}`",
                "",
                "```diff",
                suggestion["suggested_patch"].rstrip(),
                "```",
                "",
            ])
        lines.extend(["### Exact Validation Commands", ""])
        for command in workspace["validation_commands"]:
            lines.extend([
                f"#### {command['id']}",
                "",
                f"```bash\n{command['command']}\n```",
                "",
                f"- proof role: `{command['proof_role']}`",
                f"- required: `{str(command['required']).lower()}`",
                f"- status: `{command['status']}`",
                "",
            ])
    lines.extend(["## Proof Boundary", "", str(plan["proof_boundary"]), ""])
    return "\n".join(lines)


def write_outputs(out_dir: Path, plan: dict[str, Any]) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / "foundry_v1_7_normalization_execution_plan.json"
    out_md = out_dir / "foundry_v1_7_normalization_execution_plan.md"
    out_json.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(plan), encoding="utf-8")
    return out_json, out_md


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."), help="Root to scan for generated v1.7 manifests/queues.")
    parser.add_argument("--workspace", action="append", type=Path, help="Explicit workspace to consume; may be repeated.")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="Output directory for aggregate plan artifacts.")
    parser.add_argument("--seed", default=DEFAULT_SEED, help="Deterministic seed to use in suggested proof commands.")
    parser.add_argument("--print-json", action="store_true", help="Print the aggregate plan JSON to stdout.")
    args = parser.parse_args(argv)

    root = args.root.expanduser().resolve()
    if not root.is_dir():
        raise SystemExit(f"[foundry-v17-normalization-plan] ERR root not found: {root}")
    if args.workspace:
        rows = []
        for ws_arg in args.workspace:
            ws = ws_arg.expanduser().resolve()
            manifest = ws / ".auditooor" / MANIFEST_NAME
            queue = ws / ".auditooor" / QUEUE_NAME
            if not manifest.is_file() or not queue.is_file():
                raise SystemExit(f"[foundry-v17-normalization-plan] ERR missing manifest/queue for workspace: {ws}")
            rows.append({"workspace": ws, "manifest": manifest, "queue": queue})
    else:
        rows = discover_workspace_inputs(root)
    if not rows:
        raise SystemExit("[foundry-v17-normalization-plan] ERR no generated v1.7 manifest/queue pairs found")

    plan = build_plan(root, rows, args.seed)
    out_json, out_md = write_outputs(args.out_dir.expanduser().resolve(), plan)
    if args.print_json:
        print(json.dumps(plan, indent=2, sort_keys=True))
    print(
        "[foundry-v17-normalization-plan] OK "
        f"workspaces={plan['workspace_count']} queue_items={plan['queue_item_count']} "
        f"planning_items={plan['concrete_planning_item_count']} json={out_json} md={out_md}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
