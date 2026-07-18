#!/usr/bin/env python3
"""Generate planning-only artifacts for an isolated Foundry v1.7.1 trial.

This command deliberately does not install Foundry, upgrade Foundry, or run
Forge. It turns the offline inventory into operator-reviewed trial plans.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.foundry_version import PLANNED_TARGET_VERSION, build_inventory  # noqa: E402


SCHEMA_VERSION = "auditooor.foundry_v1_7_trial_plan.v1"

BASELINE_VALIDATION_COMMANDS = [
    ("baseline-version-inventory", "python3 tools/foundry-version-report.py --workspace <ws> --print-json", "Capture pre-trial Forge/Cast/Anvil provenance.", "environment_provenance_only", True),
    ("baseline-forge-build", "forge build", "Confirm the current workspace compile state before comparing v1.7.1.", "comparison_baseline", True),
    ("baseline-forge-test", "forge test", "Capture current full test behavior before the isolated target trial.", "comparison_baseline", True),
    ("baseline-targeted-poc", "forge test --match-contract <PoCOrRegressionContract> --fuzz-seed <seed>", "Anchor representative PoC/regression behavior with an explicit seed.", "comparison_baseline", True),
    ("baseline-invariant-proof-profile", "FOUNDRY_PROFILE=invariants forge test --match-contract <InvariantContract> --fuzz-seed <seed>", "Capture proof-quality invariant behavior with interval checks disabled or set to 1.", "comparison_baseline", False),
]

TARGET_VALIDATION_COMMANDS = [
    ("target-version-inventory", "PATH=<isolated-foundry-v1.7.1-bin>:$PATH python3 tools/foundry-version-report.py --workspace <ws> --print-json", "Capture isolated target tool provenance without mutating the global toolchain.", "environment_provenance_only", True),
    ("target-forge-build", "PATH=<isolated-foundry-v1.7.1-bin>:$PATH forge build", "Compare v1.7.1 compile behavior against the baseline.", "trial_comparison_only", True),
    ("target-forge-test", "PATH=<isolated-foundry-v1.7.1-bin>:$PATH forge test", "Compare full test behavior against the baseline.", "trial_comparison_only", True),
    ("target-targeted-poc", "PATH=<isolated-foundry-v1.7.1-bin>:$PATH forge test --match-contract <PoCOrRegressionContract> --fuzz-seed <seed>", "Compare representative PoC/regression behavior with deterministic fuzzing.", "trial_comparison_only", True),
    ("target-invariant-proof-profile", "PATH=<isolated-foundry-v1.7.1-bin>:$PATH FOUNDRY_PROFILE=invariants forge test --match-contract <InvariantContract> --fuzz-seed <seed>", "Compare proof-quality invariant behavior with interval checks disabled or set to 1.", "trial_comparison_only", False),
    ("target-invariant-fast-exploratory", "PATH=<isolated-foundry-v1.7.1-bin>:$PATH FOUNDRY_PROFILE=invariants_fast forge test --match-contract <InvariantContract> --fuzz-seed <seed>", "Measure v1.7.1 throughput features; never use as final proof unless interval safety is justified.", "exploratory_only_not_submission_proof", False),
    ("target-poc-execution-record", "python3 tools/poc-execution-record.py --workspace <ws> --brief <brief.md> --run '<target forge command>' --final-result needs_human --impact-assertion unknown", "Record any approved target trial run as environment evidence, not exploit proof.", "execution_manifest_if_operator_approved", False),
]

DELTA_CLASSIFIER_RULES = [
    ("expected_stricter_import_failure", ["unresolved import", "cannot resolve file", "failed to resolve import"], "v1.7.1 is stricter about stale imports/remappings.", "Normalize remappings/imports, then rerun both baseline and target commands.", "not_proof"),
    ("hardfork_or_network_default_delta", ["osaka", "prague", "hardfork", "evm version", "opcode", "precompile"], "Behavior may have changed because the workspace relies on implicit hardfork/network defaults.", "Pin evm_version/hardfork/network in foundry.toml before judging the delta.", "blocked_until_config_pinned"),
    ("random_seed_or_parallelism_delta", ["seed", "counterexample", "fuzz", "runs", "parallel"], "Fuzz behavior may be nondeterministic without an explicit seed and worker metadata.", "Replay with explicit --fuzz-seed and record workers/profile/version.", "not_final_proof"),
    ("unsafe_cheatcode_or_harness_helper_delta", ["copyStorage", "setArbitraryStorage", "Unsafe", "cheatcode"], "Existing helper code may rely on cheatcodes that are now marked unsafe.", "Refactor the helper or explicitly document why the helper remains safe.", "harness_fix_required"),
    ("environment_or_remapping_issue", ["No such file", "permission denied", "remapping", "lib/forge-std", "not found"], "The trial environment is not comparable to baseline.", "Fix isolated PATH/remappings/dependencies before interpreting test behavior.", "infrastructure_blocker"),
    ("real_harness_or_product_regression_candidate", ["assertion failed", "panic", "invariant", "revert", "counterexample"], "The delta may expose a real test, harness, or product behavior change.", "Minimize to a deterministic seed and classify against exact impact contracts.", "candidate_only_until_poc_execution_record"),
    ("no_behavior_delta", ["both pass", "same failure", "no diff"], "Baseline and target behavior match for the command pair.", "Record as compatibility evidence; do not treat as vulnerability proof.", "compatibility_evidence_only"),
    ("unknown_needs_manual_triage", [], "The delta does not match a known migration class.", "Attach baseline/target logs and classify manually before migration promotion.", "blocked_until_classified"),
]


def _commands(rows: list[tuple[str, str, str, str, bool]], phase: str) -> list[dict[str, Any]]:
    return [
        {"id": row[0], "phase": phase, "command": row[1], "purpose": row[2], "proof_role": row[3], "required": row[4]}
        for row in rows
    ]


def _classifier_rules() -> list[dict[str, Any]]:
    return [
        {"class": row[0], "signals": row[1], "meaning": row[2], "next_action": row[3], "submission_posture": row[4]}
        for row in DELTA_CLASSIFIER_RULES
    ]


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _default_out_paths(workspace: Path) -> dict[str, Path]:
    out = workspace / ".auditooor"
    return {
        "manifest_json": out / "foundry_v1_7_trial_manifest.json",
        "manifest_md": out / "foundry_v1_7_trial_manifest.md",
        "comparison_template": out / "foundry_v1_7_comparison_report_template.md",
        "delta_classifier_json": out / "foundry_v1_7_delta_classifier.json",
        "delta_classifier_md": out / "foundry_v1_7_delta_classifier.md",
        "validation_commands": out / "foundry_v1_7_validation_commands.md",
        "normalization_queue_json": out / "foundry_v1_7_config_normalization_queue.json",
        "normalization_queue_md": out / "foundry_v1_7_config_normalization_queue.md",
        "readiness_json": out / "foundry_v1_7_readiness_accounting.json",
        "readiness_md": out / "foundry_v1_7_readiness_accounting.md",
    }


def validate_manifest_shape(manifest: dict[str, Any]) -> dict[str, Any]:
    """Validate the local manifest shape without requiring jsonschema."""
    required = [
        "schema_version",
        "workspace",
        "migration_state",
        "upgrade_performed",
        "install_or_upgrade_allowed",
        "baseline",
        "target",
        "comparison",
        "config_normalization_queue",
        "readiness_accounting",
        "proof_boundary",
    ]
    command_required = ["id", "phase", "command", "purpose", "proof_role", "required"]
    errors: list[str] = []
    for key in required:
        if key not in manifest:
            errors.append(f"missing:{key}")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version_mismatch")
    if manifest.get("migration_state") != "planned_not_executed":
        errors.append("migration_state_not_planned")
    if manifest.get("upgrade_performed") is not False:
        errors.append("upgrade_performed_not_false")
    if manifest.get("install_or_upgrade_allowed") is not False:
        errors.append("install_or_upgrade_allowed_not_false")
    if manifest.get("target", {}).get("foundry_version") != PLANNED_TARGET_VERSION:
        errors.append("target_version_mismatch")
    if manifest.get("comparison", {}).get("required_pairing_key") != "command.id":
        errors.append("comparison_pairing_key_mismatch")
    for section in ("baseline", "target"):
        commands = manifest.get(section, {}).get("commands", [])
        if not isinstance(commands, list) or not commands:
            errors.append(f"{section}_commands_missing")
            continue
        for idx, command in enumerate(commands):
            for key in command_required:
                if key not in command:
                    errors.append(f"{section}_command_{idx}_missing:{key}")
            if not isinstance(command.get("required"), bool):
                errors.append(f"{section}_command_{idx}_required_not_bool")
    return {
        "schema": "docs/schemas/foundry_v1_7_trial_manifest.v1.json",
        "validated_by": "tools/foundry-v17-trial-plan.py:validate_manifest_shape",
        "valid": not errors,
        "errors": errors,
    }


def _warning_to_queue_item(index: int, warning: dict[str, Any]) -> dict[str, Any]:
    code = str(warning.get("code") or "unknown_warning")
    action_by_code = {
        "missing_explicit_hardfork": "Pin evm_version or hardfork before baseline-vs-target comparison.",
        "missing_network_key": "Add network/per-network config for forked or live-proof workspaces, or record why source-only tests do not need it.",
        "missing_fuzz_seed": "Add proof-quality seed configuration or require --fuzz-seed in validation commands.",
        "check_interval_exploratory_only": "Keep check_interval > 1 in exploratory profiles only; final proof profile should omit it or set it to 1.",
        "missing_repro_profiles": "Add profile.invariants and/or profile.fuzz_repro for deterministic proof-quality replays.",
    }
    return {
        "id": f"FN17-CONFIG-{index:03d}",
        "path": str(warning.get("path") or "workspace"),
        "source_warning_code": code,
        "action": action_by_code.get(code, "Review and normalize this Foundry config warning."),
        "reason": str(warning.get("message") or ""),
        "status": "queued",
        "blocks_final_proof": code in {"missing_explicit_hardfork", "missing_fuzz_seed", "check_interval_exploratory_only"},
        "planned_not_executed": True,
    }


def build_normalization_queue(inventory: dict[str, Any]) -> dict[str, Any]:
    scan = inventory.get("config_scan", {}) if isinstance(inventory, dict) else {}
    items = [_warning_to_queue_item(i + 1, warning) for i, warning in enumerate(scan.get("warnings") or [])]
    if scan.get("foundry_toml_count", 0) == 0:
        items.insert(0, {
            "id": "FN17-CONFIG-000",
            "path": "workspace",
            "source_warning_code": "no_foundry_toml_detected",
            "action": "Identify the Forge project root and add or point the trial at a foundry.toml before comparing versions.",
            "reason": "No Foundry config was discovered in the workspace.",
            "status": "blocked",
            "blocks_final_proof": True,
            "planned_not_executed": True,
        })
    by_code: dict[str, int] = {}
    blocking_by_code: dict[str, int] = {}
    for item in items:
        code = str(item.get("source_warning_code") or "unknown")
        by_code[code] = by_code.get(code, 0) + 1
        if item.get("blocks_final_proof"):
            blocking_by_code[code] = blocking_by_code.get(code, 0) + 1
    return {
        "schema_version": "auditooor.foundry_v1_7_config_normalization_queue.v1",
        "status": "planned_not_executed",
        "item_count": len(items),
        "blocking_item_count": sum(1 for item in items if item.get("blocks_final_proof")),
        "warning_counts": by_code,
        "blocking_warning_counts": blocking_by_code,
        "items": items,
    }


def build_readiness(inventory: dict[str, Any], queue: dict[str, Any]) -> dict[str, Any]:
    missing_tools = inventory.get("readiness_accounting", {}).get("missing_tools", [])
    blockers = []
    if missing_tools:
        blockers.append("missing_baseline_foundry_tools")
    if queue.get("item_count", 0):
        blockers.append("config_normalization_queue_not_empty")
    blocker_details = []
    for tool in missing_tools:
        blocker_details.append(
            {
                "id": f"FN17-BLOCKER-MISSING-{tool.upper()}",
                "kind": "missing_baseline_tool",
                "status": "blocked",
                "blocks": ["baseline_version_inventory", "baseline_vs_target_comparison"],
                "detail": f"`{tool}` is not present on PATH for baseline provenance.",
                "next_action": "Install or expose the existing baseline toolchain before an operator-approved isolated trial.",
            }
        )
    for item in queue.get("items", []):
        if not item.get("blocks_final_proof"):
            continue
        blocker_details.append(
            {
                "id": f"FN17-BLOCKER-{item.get('id')}",
                "kind": "config_normalization",
                "status": item.get("status", "queued"),
                "blocks": ["final_submission_proof"],
                "detail": f"{item.get('source_warning_code')} in {item.get('path')}: {item.get('reason')}",
                "next_action": item.get("action", "Normalize the config warning before final proof use."),
            }
        )
    return {
        "schema_version": "auditooor.foundry_v1_7_readiness_accounting.v1",
        "status": "planned_not_ready" if blockers else "ready_for_operator_approved_isolated_trial",
        "migration_state": "planned_not_executed",
        "blockers": blockers,
        "blocker_details": blocker_details,
        "missing_tools": missing_tools,
        "normalization_items": queue.get("item_count", 0),
        "blocking_normalization_items": len([item for item in queue.get("items", []) if item.get("blocks_final_proof")]),
        "required_artifacts": [
            "foundry_version_inventory.json",
            "foundry_v1_7_trial_manifest.json",
            "foundry_v1_7_comparison_report_template.md",
            "foundry_v1_7_delta_classifier.json",
            "foundry_v1_7_validation_commands.md",
            "foundry_v1_7_config_normalization_queue.json",
        ],
        "closeout_checks": [
            "All baseline and target logs are paired by command id.",
            "Every failing delta has a delta_classifier class.",
            "Final fuzz/invariant proof commands record explicit seed and Foundry version.",
            "Any check_interval > 1 run is marked exploratory-only or justified in the final proof.",
            "No migration artifact is described as exploit proof without poc_execution evidence.",
        ],
    }


def build_checklist_accounting(manifest: dict[str, Any], queue: dict[str, Any], readiness: dict[str, Any]) -> dict[str, Any]:
    """Summarize every concrete planning item without implying execution."""
    baseline_commands = manifest.get("baseline", {}).get("commands", [])
    target_commands = manifest.get("target", {}).get("commands", [])
    classifier_rules = _classifier_rules()
    queue_items = queue.get("items", [])
    required_artifacts = readiness.get("required_artifacts", [])
    closeout_checks = readiness.get("closeout_checks", [])
    concrete_items: list[dict[str, Any]] = []
    concrete_items.extend(
        {
            "id": f"command:{cmd.get('id')}",
            "category": "baseline_command" if cmd.get("phase") == "baseline" else "target_command",
            "status": "planned_not_executed",
            "blocks_final_proof": False,
        }
        for cmd in [*baseline_commands, *target_commands]
    )
    concrete_items.extend(
        {
            "id": f"delta-class:{rule.get('class')}",
            "category": "delta_classifier_rule",
            "status": "planned_not_executed",
            "blocks_final_proof": False,
        }
        for rule in classifier_rules
    )
    concrete_items.extend(
        {
            "id": f"config:{item.get('id')}",
            "category": "config_normalization_item",
            "status": item.get("status", "queued"),
            "blocks_final_proof": bool(item.get("blocks_final_proof")),
        }
        for item in queue_items
    )
    concrete_items.extend(
        {
            "id": f"artifact:{artifact}",
            "category": "required_artifact",
            "status": "planned_not_executed",
            "blocks_final_proof": False,
        }
        for artifact in required_artifacts
    )
    concrete_items.extend(
        {
            "id": f"closeout:{idx:02d}",
            "category": "closeout_check",
            "status": "planned_not_executed",
            "blocks_final_proof": False,
        }
        for idx, _check in enumerate(closeout_checks, start=1)
    )
    counts_by_category: dict[str, int] = {}
    for item in concrete_items:
        category = str(item["category"])
        counts_by_category[category] = counts_by_category.get(category, 0) + 1
    return {
        "schema_version": "auditooor.foundry_v1_7_checklist_accounting.v1",
        "status": "planned_not_executed",
        "baseline_command_count": len(baseline_commands),
        "target_command_count": len(target_commands),
        "delta_classifier_rule_count": len(classifier_rules),
        "normalization_queue_item_count": len(queue_items),
        "required_artifact_count": len(required_artifacts),
        "closeout_check_count": len(closeout_checks),
        "concrete_checklist_item_count": len(concrete_items),
        "blocking_checklist_item_count": sum(1 for item in concrete_items if item.get("blocks_final_proof")),
        "counts_by_category": counts_by_category,
        "items": concrete_items,
        "proof_boundary": "Checklist/accounting only; planned items are not execution evidence.",
    }


def build_manifest(workspace: Path, inventory: dict[str, Any], queue: dict[str, Any], readiness: dict[str, Any]) -> dict[str, Any]:
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "migration_state": "planned_not_executed",
        "upgrade_performed": False,
        "install_or_upgrade_allowed": False,
        "baseline": {
            "source": "current offline inventory",
            "foundry_versions": inventory.get("current_version_summary", {}),
            "inventory_path": ".auditooor/foundry_version_inventory.json",
            "commands": _commands(BASELINE_VALIDATION_COMMANDS, "baseline"),
        },
        "target": {
            "foundry_version": PLANNED_TARGET_VERSION,
            "isolation_requirement": "Use an isolated PATH/worktree/toolchain approved by the operator; do not mutate the global Foundry install.",
            "commands": _commands(TARGET_VALIDATION_COMMANDS, "target_v1_7"),
        },
        "comparison": {
            "report_template_path": ".auditooor/foundry_v1_7_comparison_report_template.md",
            "delta_classifier_path": ".auditooor/foundry_v1_7_delta_classifier.json",
            "required_pairing_key": "command.id",
        },
        "config_normalization_queue": {
            "path": ".auditooor/foundry_v1_7_config_normalization_queue.json",
            "item_count": queue.get("item_count", 0),
        },
        "readiness_accounting": readiness,
        "proof_boundary": "Planning artifacts only; not installation evidence, execution evidence, or exploit proof.",
    }
    manifest["checklist_accounting"] = build_checklist_accounting(manifest, queue, readiness)
    manifest["schema_validation"] = validate_manifest_shape(manifest)
    return manifest


def render_manifest_md(manifest: dict[str, Any]) -> str:
    lines = [
        "# Foundry v1.7.1 Isolated Trial Manifest",
        "",
        f"Workspace: `{manifest.get('workspace')}`",
        "",
        "Status: `planned_not_executed`; no install, upgrade, Forge run, push, PR, or submission proof was performed.",
        "",
        f"Target: `{manifest.get('target', {}).get('foundry_version', PLANNED_TARGET_VERSION)}`",
        "",
        "## Baseline Commands",
        "",
    ]
    lines.extend(f"- `{cmd['id']}`: `{cmd['command']}`" for cmd in manifest["baseline"]["commands"])
    lines.extend(["", "## Target Commands", ""])
    lines.extend(f"- `{cmd['id']}`: `{cmd['command']}`" for cmd in manifest["target"]["commands"])
    readiness = manifest.get("readiness_accounting", {})
    schema_validation = manifest.get("schema_validation", {})
    lines.extend([
        "",
        "## Readiness",
        "",
        f"- status: `{readiness.get('status')}`",
        f"- blockers: `{', '.join(readiness.get('blockers', [])) or 'none'}`",
        f"- normalization items: `{readiness.get('normalization_items', 0)}`",
        f"- blocking details: `{len(readiness.get('blocker_details', []))}`",
        "",
        "## Checklist Accounting",
        "",
        f"- concrete items: `{manifest.get('checklist_accounting', {}).get('concrete_checklist_item_count', 0)}`",
        f"- blocking items: `{manifest.get('checklist_accounting', {}).get('blocking_checklist_item_count', 0)}`",
        "",
        "## Schema Validation",
        "",
        f"- schema: `{schema_validation.get('schema')}`",
        f"- valid: `{str(schema_validation.get('valid')).lower()}`",
        f"- errors: `{', '.join(schema_validation.get('errors', [])) or 'none'}`",
        "",
        "## Proof Boundary",
        "",
        str(manifest.get("proof_boundary", "")),
        "",
    ])
    return "\n".join(lines)


def render_comparison_template(manifest: dict[str, Any]) -> str:
    lines = ["# Foundry v1.7.1 Baseline-vs-Target Comparison Report", "", "Status: `template_only_planned_not_executed`", "", "Use this after an operator-approved isolated trial. Do not fill it with inferred results.", "", "| Command ID | Baseline log | Target log | Baseline result | Target result | Delta class | Decision |", "|---|---|---|---|---|---|---|"]
    lines.extend(f"| `{cmd['id']}` | TBD | TBD | TBD | TBD | TBD | TBD |" for cmd in manifest["baseline"]["commands"])
    lines.extend(["", "## Required Closeout", "", "- Every target command must reference the isolated v1.7.1 inventory.", "- Every non-matching result must use a class from `foundry_v1_7_delta_classifier.json`.", "- Any final proof candidate still needs `poc_execution/**/execution_manifest.json` and exact impact evidence.", "- Any `invariants_fast` / `check_interval > 1` result remains exploratory unless separately justified.", ""])
    return "\n".join(lines)


def render_classifier_md() -> str:
    lines = ["# Foundry v1.7.1 Delta Classifier", "", "Status: `planned_not_executed`", ""]
    for rule in _classifier_rules():
        lines.extend([f"## {rule['class']}", "", f"- meaning: {rule['meaning']}", f"- signals: `{', '.join(rule['signals']) or 'manual fallback'}`", f"- next action: {rule['next_action']}", f"- submission posture: `{rule['submission_posture']}`", ""])
    return "\n".join(lines)


def render_validation_commands(manifest: dict[str, Any]) -> str:
    lines = ["# Foundry v1.7.1 Validation Command List", "", "Status: `planned_not_executed`", ""]
    for section in ("baseline", "target"):
        lines.extend([f"## {section.title()}", ""])
        for cmd in manifest[section]["commands"]:
            lines.extend([f"### {cmd['id']}", "", f"```bash\n{cmd['command']}\n```", "", f"- purpose: {cmd['purpose']}", f"- proof role: `{cmd['proof_role']}`", f"- required: `{str(cmd['required']).lower()}`", ""])
    return "\n".join(lines)


def render_queue_md(queue: dict[str, Any]) -> str:
    lines = [
        "# Foundry v1.7.1 Config Normalization Queue",
        "",
        "Status: `planned_not_executed`",
        "",
        f"- total items: `{queue.get('item_count', 0)}`",
        f"- blocking items: `{queue.get('blocking_item_count', 0)}`",
        "",
    ]
    if not queue.get("items"):
        return "\n".join(lines + ["- none", ""])
    for item in queue["items"]:
        lines.extend([f"## {item['id']}", "", f"- path: `{item['path']}`", f"- warning: `{item['source_warning_code']}`", f"- action: {item['action']}", f"- blocks final proof: `{str(item['blocks_final_proof']).lower()}`", f"- status: `{item['status']}`", ""])
    return "\n".join(lines)


def render_readiness_md(readiness: dict[str, Any]) -> str:
    lines = ["# Foundry v1.7.1 Readiness Accounting", "", f"Status: `{readiness.get('status')}`", "", f"- migration state: `{readiness.get('migration_state')}`", f"- blockers: `{', '.join(readiness.get('blockers', [])) or 'none'}`", f"- missing tools: `{', '.join(readiness.get('missing_tools', [])) or 'none'}`", f"- normalization items: `{readiness.get('normalization_items', 0)}`", f"- blocking normalization items: `{readiness.get('blocking_normalization_items', 0)}`", "", "## Closeout Checks", ""]
    lines.extend(f"- {check}" for check in readiness.get("closeout_checks", []))
    lines.extend(["", "## Exact Blockers", ""])
    blocker_details = readiness.get("blocker_details", [])
    if blocker_details:
        for blocker in blocker_details:
            lines.extend(
                [
                    f"- `{blocker.get('id')}`: {blocker.get('detail')}",
                    f"  next action: {blocker.get('next_action')}",
                ]
            )
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


def write_outputs(paths: dict[str, Path], manifest: dict[str, Any], queue: dict[str, Any], readiness: dict[str, Any]) -> None:
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    paths["manifest_json"].write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["manifest_md"].write_text(render_manifest_md(manifest), encoding="utf-8")
    paths["comparison_template"].write_text(render_comparison_template(manifest), encoding="utf-8")
    paths["delta_classifier_json"].write_text(json.dumps({"schema_version": "auditooor.foundry_v1_7_delta_classifier.v1", "status": "planned_not_executed", "rules": _classifier_rules()}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["delta_classifier_md"].write_text(render_classifier_md(), encoding="utf-8")
    paths["validation_commands"].write_text(render_validation_commands(manifest), encoding="utf-8")
    paths["normalization_queue_json"].write_text(json.dumps(queue, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["normalization_queue_md"].write_text(render_queue_md(queue), encoding="utf-8")
    paths["readiness_json"].write_text(json.dumps(readiness, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["readiness_md"].write_text(render_readiness_md(readiness), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path, help="Workspace whose .auditooor/ planning artifacts should be written.")
    parser.add_argument("--inventory-json", type=Path, help="Existing foundry_version_inventory.json to reuse.")
    parser.add_argument("--print-json", action="store_true", help="Print the trial manifest JSON to stdout.")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit(f"[foundry-v17-trial-plan] ERR workspace not found: {workspace}")
    inventory_path = args.inventory_json.expanduser().resolve() if args.inventory_json else workspace / ".auditooor" / "foundry_version_inventory.json"
    inventory = _load_json(inventory_path) if inventory_path.is_file() else None
    if inventory is None:
        inventory = build_inventory(workspace)
    queue = build_normalization_queue(inventory)
    readiness = build_readiness(inventory, queue)
    manifest = build_manifest(workspace, inventory, queue, readiness)
    paths = _default_out_paths(workspace)
    write_outputs(paths, manifest, queue, readiness)
    if args.print_json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"[foundry-v17-trial-plan] OK state={manifest['migration_state']} artifacts={len(paths)} readiness={readiness['status']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
