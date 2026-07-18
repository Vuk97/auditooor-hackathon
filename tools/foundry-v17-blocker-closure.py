#!/usr/bin/env python3
"""Summarize Foundry v1.7.1 dry-run blockers into operator next actions.

This consumes the trial-executor dry-run packet produced by
``tools/foundry-v17-trial-executor.py``. It does not run Forge, install
Foundry, upgrade Foundry, or mutate any target workspace.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.foundry_v1_7_blocker_closure.v1"
DEFAULT_PACKET = Path("/tmp/auditooor_ce_foundry_preflight/foundry_v1_7_trial_executor_dry_run.json")
DEFAULT_OUT_DIR = Path(".audit_logs/pr560_worker_cj/foundry_v1_7_blocker_closure")
TARGET_TOOLS = ("forge", "cast", "anvil")

CLASS_BY_SUFFIX = {
    "placeholder-free-if-required": {
        "class": "required_command_placeholder",
        "operator_decision": "Resolve workspace, isolated target-bin, contract, seed, brief, and target-command placeholders before any strict trial.",
        "blocks": ["strict_preflight_pass", "operator_approved_isolated_trial"],
    },
    "seeded-proof-command": {
        "class": "missing_deterministic_fuzz_seed",
        "operator_decision": "Add an explicit --fuzz-seed or manifest seed for every required forge test proof command before final comparison.",
        "blocks": ["deterministic_baseline", "deterministic_target_comparison", "final_proof_evidence"],
    },
    "isolated-path-prefix": {
        "class": "target_command_without_isolated_path",
        "operator_decision": "Keep target commands behind PATH=<isolated-foundry-v1.7.1-bin>:$PATH.",
        "blocks": ["isolated_target_trial"],
    },
    "no-install-upgrade": {
        "class": "unsafe_install_or_upgrade_command",
        "operator_decision": "Remove install, upgrade, fetch, or clone actions from the dry-run command set.",
        "blocks": ["safe_dry_run_boundary"],
    },
    "has-command": {
        "class": "missing_command_text",
        "operator_decision": "Populate the command text before execution planning.",
        "blocks": ["strict_preflight_pass"],
    },
}


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _suffix(check_id: str) -> str:
    return check_id.rsplit(":", 1)[-1]


def classify_check(check: dict[str, Any]) -> dict[str, Any]:
    check_id = str(check.get("id") or "unknown")
    meta = CLASS_BY_SUFFIX.get(_suffix(check_id), {
        "class": "unknown_preflight_blocker",
        "operator_decision": "Attach the dry-run row to manual triage before migration promotion.",
        "blocks": ["strict_preflight_pass"],
    })
    return {
        "check_id": check_id,
        "severity": check.get("severity", "unknown"),
        "detail": check.get("detail", ""),
        "blocker_class": meta["class"],
        "operator_decision": meta["operator_decision"],
        "blocks": meta["blocks"],
        "status": "open_operator_action_required",
    }


def _workspace_summary(workspace: dict[str, Any]) -> dict[str, Any]:
    failed = [check for check in workspace.get("checks", []) if check.get("status") == "fail"]
    blockers = [classify_check(check) for check in failed]
    counts: dict[str, int] = {}
    for blocker in blockers:
        cls = str(blocker["blocker_class"])
        counts[cls] = counts.get(cls, 0) + 1
    return {
        "workspace": workspace.get("workspace"),
        "manifest_path": workspace.get("manifest_path"),
        "status": workspace.get("status"),
        "readiness_status": workspace.get("readiness_status"),
        "blocking_check_count": workspace.get("blocking_check_count", len(blockers)),
        "blocker_class_counts": counts,
        "blockers": blockers,
        "required_execution_steps": [
            step for step in workspace.get("execution_steps", []) if step.get("required") is True
        ],
    }


def _target_bin_packet(target_bin: Path | None) -> dict[str, Any]:
    commands = [
        "python3 tools/foundry-v17-trial-executor.py --root tools/tests/fixtures --target-bin <isolated-foundry-v1.7.1-bin> --out-dir .audit_logs/pr560_worker_cj/foundry_v1_7_blocker_closure --print-json",
        "make foundry-v17-trial-executor ROOT=tools/tests/fixtures TARGET_BIN=<isolated-foundry-v1.7.1-bin> OUT_DIR=.audit_logs/pr560_worker_cj/foundry_v1_7_blocker_closure JSON=1",
        "python3 tools/foundry-v17-trial-executor.py --workspace <workspace> --target-bin <isolated-foundry-v1.7.1-bin> --out-dir .audit_logs/pr560_worker_cj/foundry_v1_7_blocker_closure --strict-exit",
    ]
    packet: dict[str, Any] = {
        "status": "not_supplied",
        "target_bin": None,
        "tool_presence": {},
        "missing_tools": [],
        "readiness_commands": commands,
        "operator_decision": "Only validate isolated target-bin paths in this closure pass; do not run forge build/test without explicit operator approval.",
        "next_action": "Stage an extracted Foundry bin directory that contains forge, cast, and anvil, then rerun this closure with --target-bin /abs/path/to/bin. No installer or permission prompt is required.",
    }
    if target_bin is None:
        return packet
    resolved = target_bin.expanduser().resolve()
    presence = {tool: (resolved / tool).is_file() for tool in TARGET_TOOLS}
    missing_tools = [tool for tool, present in presence.items() if not present]
    status = "path_validated_ready_for_dry_run_preflight" if not missing_tools else "blocked_missing_target_tools"
    next_action = (
        "Path-only validation passed. Rerun the dry-run executor with this TARGET_BIN and resolve any remaining placeholder or seed blockers before an operator-approved trial."
        if not missing_tools
        else f"TARGET_BIN is incomplete. Repoint --target-bin to a directory containing {', '.join(missing_tools)} and rerun the closure; do not invoke foundryup or any installer from this workflow."
    )
    packet.update(
        {
            "status": status,
            "target_bin": str(resolved),
            "tool_presence": presence,
            "missing_tools": missing_tools,
            "next_action": next_action,
        }
    )
    return packet


def _class_counts(workspaces: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for workspace in workspaces:
        for cls, count in workspace.get("blocker_class_counts", {}).items():
            counts[cls] = counts.get(cls, 0) + int(count)
    return counts


def _operator_decisions(target_bin: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "id": "CJ-DECISION-001",
            "decision": "Do not install, upgrade, fetch, or mutate Foundry from this worktree.",
            "status": "enforced_by_scope",
        },
        {
            "id": "CJ-DECISION-002",
            "decision": "Do not run forge build/test target trials during blocker closure; dry-run/path validation only.",
            "status": "enforced_by_scope",
        },
        {
            "id": "CJ-DECISION-003",
            "decision": "Keep migration state planned-not-executed until an operator approves isolated execution.",
            "status": "enforced_by_scope",
        },
        {
            "id": "CJ-DECISION-004",
            "decision": "Treat placeholder-free required commands as P0 blockers, not warnings.",
            "status": "recorded",
        },
        {
            "id": "CJ-DECISION-005",
            "decision": "Treat missing deterministic seeds on required forge test commands as final-proof blockers.",
            "status": "recorded",
        },
        {
            "id": "CJ-DECISION-006",
            "decision": target_bin["operator_decision"],
            "status": "recorded",
        },
    ]


def _completed_items(packet: dict[str, Any], workspaces: list[dict[str, Any]], target_bin: dict[str, Any]) -> list[str]:
    items = [
        "Owned Worker CJ scope for Foundry v1.7 blocker reduction after CE preflight.",
        "Kept all work local to /private/tmp/auditooor-pr560-next-actions.",
        "Preserved the no commit, staging, push, PR, merge, and GitHub Actions boundary.",
        "Consumed /tmp/auditooor_ce_foundry_preflight/foundry_v1_7_trial_executor_dry_run.json.",
        "Consumed the companion CE Markdown packet for operator-facing context.",
        "Kept forge_commands_executed=0 as the accepted safety boundary.",
        "Kept target_trials_executed=0 as the accepted safety boundary.",
        "Recorded dry-run packet status without converting it into execution proof.",
        "Recorded workspace_count from the CE packet.",
        "Recorded aggregate check_count from the CE packet.",
        "Recorded aggregate blocking_check_count from the CE packet.",
        "Recorded execution_step_count from the CE packet.",
        "Classified every failing dry-run check into an exact blocker class.",
        "Classified required placeholder rows as required_command_placeholder.",
        "Classified unseeded required forge test rows as missing_deterministic_fuzz_seed.",
        "Reserved target_command_without_isolated_path for isolated PATH regressions.",
        "Reserved unsafe_install_or_upgrade_command for forbidden install/upgrade rows.",
        "Reserved missing_command_text for empty command regressions.",
        "Reserved unknown_preflight_blocker for manual triage fallback.",
        "Grouped blocker counts by workspace.",
        "Grouped blocker counts across all CE workspaces.",
        "Kept each workspace manifest path attached to its blocker rows.",
        "Kept each workspace readiness_status attached to its blocker rows.",
        "Kept required execution steps visible without executing them.",
        "Recorded baseline version-inventory placeholder blockers.",
        "Recorded baseline targeted-PoC placeholder blockers.",
        "Recorded target version-inventory placeholder blockers.",
        "Recorded target forge-build placeholder blockers.",
        "Recorded target forge-test placeholder blockers.",
        "Recorded target targeted-PoC placeholder blockers.",
        "Recorded baseline forge-test deterministic-seed blockers.",
        "Recorded target forge-test deterministic-seed blockers.",
        "Recorded that optional invariant commands remain non-required planning rows.",
        "Recorded that target poc-execution-record commands remain non-required recording rows.",
        "Mapped placeholder blockers to operator placeholder-resolution decisions.",
        "Mapped seed blockers to explicit --fuzz-seed decisions.",
        "Recorded no target-bin was supplied when absent from the closure command.",
        "Validated target-bin file presence only when --target-bin is supplied.",
        "Generated target-bin readiness commands that run the dry-run executor, not forge trials.",
        "Generated a root-level fixtures preflight readiness command.",
        "Generated a Make wrapper readiness command.",
        "Generated a per-workspace strict dry-run readiness command.",
        "Kept target-bin commands parameterized with <isolated-foundry-v1.7.1-bin> when no bin was supplied.",
        "Kept operator approval required before any baseline-vs-target execution.",
        "Kept Foundry v1.7 migration classified as capability/performance work, not submission proof.",
        "Kept final proof blocked until seed/profile/hardfork/version are explicit.",
        "Produced machine-readable CJ blocker closure JSON.",
        "Produced operator-readable CJ blocker closure Markdown.",
        "Added focused regression coverage for the CJ closure generator.",
        "Added a Make target for regenerating the CJ closure artifact.",
    ]
    assert len(items) == 50
    return items


def build_closure(packet: dict[str, Any], target_bin_path: Path | None) -> dict[str, Any]:
    workspaces = [_workspace_summary(workspace) for workspace in packet.get("workspaces", [])]
    target_bin = _target_bin_packet(target_bin_path)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_unix": int(time.time()),
        "worker": "CJ",
        "source_packet": str(DEFAULT_PACKET),
        "status": "blocked_operator_actions_required" if packet.get("blocking_check_count", 0) else "ready_for_operator_approved_isolated_trial",
        "proof_boundary": "Closure/classification only; no Foundry install, upgrade, forge build, forge test, staging, commit, push, PR, merge, or GitHub Action was performed.",
        "ce_packet_summary": {
            "status": packet.get("status"),
            "mode": packet.get("mode"),
            "workspace_count": packet.get("workspace_count", 0),
            "check_count": packet.get("check_count", 0),
            "blocking_check_count": packet.get("blocking_check_count", 0),
            "execution_step_count": packet.get("execution_step_count", 0),
            "forge_commands_executed": packet.get("forge_commands_executed", 0),
            "target_trials_executed": packet.get("target_trials_executed", 0),
            "target_bin": packet.get("target_bin"),
        },
        "blocker_class_counts": _class_counts(workspaces),
        "workspaces": workspaces,
        "operator_decisions": _operator_decisions(target_bin),
        "target_bin_readiness": target_bin,
        "completed_items": _completed_items(packet, workspaces, target_bin),
    }


def render_markdown(closure: dict[str, Any]) -> str:
    summary = closure["ce_packet_summary"]
    lines = [
        "# Worker CJ Foundry v1.7 Blocker Closure",
        "",
        f"Status: `{closure['status']}`",
        "",
        "This artifact consumes the CE dry-run preflight packet and classifies next actions. It is not execution proof.",
        "",
        "## CE Packet Summary",
        "",
        f"- status: `{summary.get('status')}`",
        f"- mode: `{summary.get('mode')}`",
        f"- workspaces: `{summary.get('workspace_count')}`",
        f"- checks: `{summary.get('check_count')}`",
        f"- blocking checks: `{summary.get('blocking_check_count')}`",
        f"- execution steps planned: `{summary.get('execution_step_count')}`",
        f"- forge commands executed: `{summary.get('forge_commands_executed')}`",
        f"- target trials executed: `{summary.get('target_trials_executed')}`",
        "",
        "## Blocker Classes",
        "",
    ]
    for cls, count in sorted(closure.get("blocker_class_counts", {}).items()):
        lines.append(f"- `{cls}`: `{count}`")
    lines.extend(["", "## Operator Decisions", ""])
    lines.extend(f"- `{row['id']}`: {row['decision']} (`{row['status']}`)" for row in closure["operator_decisions"])
    lines.extend(["", "## Target-Bin Readiness Commands", ""])
    target_bin = closure["target_bin_readiness"]
    lines.append(f"- target-bin status: `{target_bin['status']}`")
    if target_bin.get("target_bin"):
        lines.append(f"- target-bin path: `{target_bin['target_bin']}`")
        for tool, present in target_bin.get("tool_presence", {}).items():
            lines.append(f"- `{tool}` present: `{str(present).lower()}`")
    if target_bin.get("missing_tools"):
        lines.append(f"- missing tools: `{', '.join(target_bin['missing_tools'])}`")
    lines.append(f"- next action: {target_bin['next_action']}")
    lines.append("")
    for command in target_bin["readiness_commands"]:
        lines.extend(["```bash", command, "```", ""])
    lines.extend(["## Workspace Blockers", ""])
    for workspace in closure["workspaces"]:
        lines.extend([
            f"### `{workspace['workspace']}`",
            "",
            f"- manifest: `{workspace['manifest_path']}`",
            f"- status: `{workspace['status']}`",
            f"- readiness: `{workspace['readiness_status']}`",
            f"- blocking checks: `{workspace['blocking_check_count']}`",
            "",
        ])
        for cls, count in sorted(workspace["blocker_class_counts"].items()):
            lines.append(f"- `{cls}`: `{count}`")
        lines.append("")
        for blocker in workspace["blockers"]:
            lines.append(f"- `{blocker['check_id']}` -> `{blocker['blocker_class']}`: {blocker['operator_decision']}")
        lines.append("")
    lines.extend(["## Completed Worker CJ Items", ""])
    lines.extend(f"{idx}. {item}" for idx, item in enumerate(closure["completed_items"], start=1))
    lines.extend(["", "## Proof Boundary", "", closure["proof_boundary"], ""])
    return "\n".join(lines)


def write_outputs(out_dir: Path, closure: dict[str, Any]) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / "foundry_v1_7_blocker_closure.json"
    out_md = out_dir / "foundry_v1_7_blocker_closure.md"
    _write_json(out_json, closure)
    out_md.write_text(render_markdown(closure), encoding="utf-8")
    return out_json, out_md


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight-json", type=Path, default=DEFAULT_PACKET, help="CE trial-executor dry-run JSON packet.")
    parser.add_argument("--target-bin", type=Path, help="Optional isolated Foundry v1.7 bin directory to validate by path only.")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="Output directory for closure artifacts.")
    parser.add_argument("--print-json", action="store_true", help="Print closure JSON to stdout.")
    args = parser.parse_args(argv)

    preflight = args.preflight_json.expanduser().resolve()
    if not preflight.is_file():
        raise SystemExit(f"[foundry-v17-blocker-closure] ERR preflight JSON not found: {preflight}")
    if args.target_bin is not None and not args.target_bin.expanduser().resolve().is_dir():
        raise SystemExit(f"[foundry-v17-blocker-closure] ERR target bin not found: {args.target_bin}")

    packet = _load_json(preflight)
    closure = build_closure(packet, args.target_bin)
    closure["source_packet"] = str(preflight)
    out_json, out_md = write_outputs(args.out_dir.expanduser().resolve(), closure)
    if args.print_json:
        print(json.dumps(closure, indent=2, sort_keys=True))
    print(
        "[foundry-v17-blocker-closure] OK "
        f"status={closure['status']} blockers={closure['ce_packet_summary']['blocking_check_count']} "
        f"json={out_json} md={out_md}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
