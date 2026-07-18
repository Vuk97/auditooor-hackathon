#!/usr/bin/env python3
"""Dry-run preflight for operator-approved Foundry v1.7.1 trial execution.

This command validates generated v1.7 trial manifests and writes an execution
readiness packet. It deliberately does not install Foundry, upgrade Foundry, or
run Forge. The output is a baseline-vs-target command manifest that is safe for
operator review before any isolated trial is approved.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.foundry_v1_7_trial_executor_dry_run.v1"
TRIAL_SCHEMA_VERSION = "auditooor.foundry_v1_7_trial_plan.v1"
TARGET_VERSION = "v1.7.1"
DEFAULT_OUT_DIR = Path(".audit_logs/pr560_worker_ce/foundry_v1_7_trial_preflight")
MANIFEST_NAME = "foundry_v1_7_trial_manifest.json"
PLACEHOLDER_RE = re.compile(r"<[^>\n]+>")
FORBIDDEN_COMMAND_RE = re.compile(r"\b(foundryup|curl|brew|cargo\s+install|git\s+clone)\b")


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _command_suffix(command_id: str) -> str:
    for prefix in ("baseline-", "target-"):
        if command_id.startswith(prefix):
            return command_id[len(prefix):]
    return command_id


def _discover_manifests(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob(MANIFEST_NAME) if ".git" not in path.parts)


def _command_check(command: dict[str, Any], section: str) -> list[dict[str, Any]]:
    command_id = str(command.get("id") or "missing-id")
    raw_command = str(command.get("command") or "")
    checks = [
        {
            "id": f"{section}:{command_id}:has-command",
            "status": "pass" if raw_command else "fail",
            "severity": "P0",
            "detail": "Command text is present.",
        },
        {
            "id": f"{section}:{command_id}:no-install-upgrade",
            "status": "fail" if FORBIDDEN_COMMAND_RE.search(raw_command) else "pass",
            "severity": "P0",
            "detail": "Command does not install, upgrade, or fetch a toolchain.",
        },
        {
            "id": f"{section}:{command_id}:placeholder-free-if-required",
            "status": "fail" if command.get("required") and PLACEHOLDER_RE.search(raw_command) else "pass",
            "severity": "P0",
            "detail": "Required commands must not contain unresolved placeholders.",
        },
    ]
    if section == "target" and command.get("proof_role") != "execution_manifest_if_operator_approved":
        checks.append(
            {
                "id": f"{section}:{command_id}:isolated-path-prefix",
                "status": "pass" if re.search(r"\bPATH=\S+:\$PATH\b", raw_command) else "fail",
                "severity": "P0",
                "detail": "Target commands must use the isolated v1.7 PATH prefix.",
            }
        )
    if command.get("required") and ("forge test" in raw_command or "FOUNDRY_PROFILE" in raw_command):
        checks.append(
            {
                "id": f"{section}:{command_id}:seeded-proof-command",
                "status": "pass" if "--fuzz-seed" in raw_command or "seed" in raw_command else "fail",
                "severity": "P0",
                "detail": "Required fuzz/test proof commands must be deterministic.",
            }
        )
    return checks


def _manifest_checks(manifest: dict[str, Any], manifest_path: Path, root: Path, target_bin: Path | None) -> list[dict[str, Any]]:
    baseline_commands = manifest.get("baseline", {}).get("commands") or []
    target_commands = manifest.get("target", {}).get("commands") or []
    baseline_ids = {str(command.get("id") or "") for command in baseline_commands}
    target_ids = {str(command.get("id") or "") for command in target_commands}
    baseline_suffixes = {_command_suffix(command_id) for command_id in baseline_ids}
    target_suffixes = {_command_suffix(command_id) for command_id in target_ids}
    required_pair_suffixes = sorted(
        _command_suffix(command_id)
        for command_id in baseline_ids
        if command_id.startswith("baseline-")
    )
    checks: list[dict[str, Any]] = [
        {
            "id": "manifest:schema-version",
            "status": "pass" if manifest.get("schema_version") == TRIAL_SCHEMA_VERSION else "fail",
            "severity": "P0",
            "detail": f"Manifest uses {TRIAL_SCHEMA_VERSION}.",
        },
        {
            "id": "manifest:planned-not-executed",
            "status": "pass" if manifest.get("migration_state") == "planned_not_executed" else "fail",
            "severity": "P0",
            "detail": "Dry-run input must not already claim migration execution.",
        },
        {
            "id": "manifest:no-upgrade-performed",
            "status": "pass" if manifest.get("upgrade_performed") is False else "fail",
            "severity": "P0",
            "detail": "Manifest guardrail keeps upgrade_performed=false.",
        },
        {
            "id": "manifest:no-install-upgrade-allowed",
            "status": "pass" if manifest.get("install_or_upgrade_allowed") is False else "fail",
            "severity": "P0",
            "detail": "Manifest guardrail keeps install_or_upgrade_allowed=false.",
        },
        {
            "id": "manifest:target-version",
            "status": "pass" if manifest.get("target", {}).get("foundry_version") == TARGET_VERSION else "fail",
            "severity": "P0",
            "detail": f"Target version is {TARGET_VERSION}.",
        },
        {
            "id": "manifest:schema-validation-clean",
            "status": "pass" if manifest.get("schema_validation", {}).get("valid") is True else "fail",
            "severity": "P0",
            "detail": "Embedded stdlib schema validation must be clean.",
        },
        {
            "id": "manifest:comparison-pairing-key",
            "status": "pass" if manifest.get("comparison", {}).get("required_pairing_key") == "command.id" else "fail",
            "severity": "P0",
            "detail": "Baseline/target comparison is paired by command id.",
        },
        {
            "id": "manifest:has-baseline-commands",
            "status": "pass" if baseline_commands else "fail",
            "severity": "P0",
            "detail": "Baseline command list is present.",
        },
        {
            "id": "manifest:has-target-commands",
            "status": "pass" if target_commands else "fail",
            "severity": "P0",
            "detail": "Target command list is present.",
        },
        {
            "id": "manifest:readiness-accounting-present",
            "status": "pass" if isinstance(manifest.get("readiness_accounting"), dict) else "fail",
            "severity": "P0",
            "detail": "Readiness accounting is present.",
        },
        {
            "id": "manifest:proof-boundary-present",
            "status": "pass" if "Planning artifacts only" in str(manifest.get("proof_boundary") or "") else "fail",
            "severity": "P0",
            "detail": "Manifest does not overclaim execution or exploit proof.",
        },
    ]
    for suffix in required_pair_suffixes:
        checks.append(
            {
                "id": f"pair:{suffix}",
                "status": "pass" if suffix in target_suffixes else "fail",
                "severity": "P0",
                "detail": f"Baseline command `{suffix}` has a target command counterpart.",
            }
        )
    checks.extend(
        {
            "id": f"target-extra:{suffix}:allowed",
            "status": "pass" if suffix in {"invariant-fast-exploratory", "poc-execution-record"} else "fail",
            "severity": "P1",
            "detail": "Unpaired target-only commands must be exploratory or recording-only.",
        }
        for suffix in sorted(target_suffixes - baseline_suffixes)
    )
    for section, commands in (("baseline", baseline_commands), ("target", target_commands)):
        for command in commands:
            checks.extend(_command_check(command, section))
    if target_bin is not None:
        checks.extend(
            {
                "id": f"target-bin:{tool}:present",
                "status": "pass" if (target_bin / tool).is_file() else "fail",
                "severity": "P0",
                "detail": f"Dry-run target bin contains `{tool}`; the tool is not executed.",
            }
            for tool in ("forge", "cast", "anvil")
        )
    checks.append(
        {
            "id": "manifest:path-recorded",
            "status": "pass",
            "severity": "info",
            "detail": _rel(manifest_path, root),
        }
    )
    return checks


def _status(checks: list[dict[str, Any]]) -> str:
    return "pass" if all(check["status"] == "pass" or check["severity"] == "info" for check in checks) else "blocked"


def build_workspace_packet(manifest_path: Path, root: Path, target_bin: Path | None) -> dict[str, Any]:
    manifest = _load_json(manifest_path)
    workspace = Path(str(manifest.get("workspace") or manifest_path.parent.parent)).resolve()
    checks = _manifest_checks(manifest, manifest_path, root, target_bin)
    baseline_commands = manifest.get("baseline", {}).get("commands") or []
    target_commands = manifest.get("target", {}).get("commands") or []
    blocking = [check for check in checks if check["status"] == "fail" and check["severity"] in {"P0", "P1"}]
    execution_steps = [
        {
            "id": command.get("id"),
            "phase": command.get("phase"),
            "command": command.get("command"),
            "status": "dry_run_only_not_executed",
            "required": command.get("required"),
        }
        for command in [*baseline_commands, *target_commands]
    ]
    return {
        "workspace": str(workspace),
        "manifest_path": _rel(manifest_path, root),
        "status": _status(checks),
        "check_count": len(checks),
        "blocking_check_count": len(blocking),
        "checks": checks,
        "execution_step_count": len(execution_steps),
        "execution_steps": execution_steps,
        "readiness_status": manifest.get("readiness_accounting", {}).get("status", "unknown"),
        "proof_boundary": "Dry-run validation only; no Foundry commands were executed.",
    }


def build_packet(root: Path, manifests: list[Path], target_bin: Path | None) -> dict[str, Any]:
    workspaces = [build_workspace_packet(path, root, target_bin) for path in manifests]
    total_checks = sum(workspace["check_count"] for workspace in workspaces)
    total_blocking = sum(workspace["blocking_check_count"] for workspace in workspaces)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_unix": int(time.time()),
        "root": str(root),
        "status": "pass" if total_blocking == 0 else "blocked",
        "mode": "dry_run",
        "upgrade_performed": False,
        "install_or_upgrade_allowed": False,
        "forge_commands_executed": 0,
        "target_trials_executed": 0,
        "target_bin": str(target_bin) if target_bin else None,
        "workspace_count": len(workspaces),
        "check_count": total_checks,
        "blocking_check_count": total_blocking,
        "execution_step_count": sum(workspace["execution_step_count"] for workspace in workspaces),
        "workspaces": workspaces,
        "proof_boundary": "Dry-run preflight only; operator approval is still required before isolated execution.",
    }


def render_markdown(packet: dict[str, Any]) -> str:
    lines = [
        "# Foundry v1.7.1 Trial Executor Dry Run",
        "",
        "Status: `{}`".format(packet["status"]),
        "",
        "- mode: `dry_run`",
        f"- workspaces: `{packet['workspace_count']}`",
        f"- checks: `{packet['check_count']}`",
        f"- blocking checks: `{packet['blocking_check_count']}`",
        f"- execution steps planned: `{packet['execution_step_count']}`",
        "- forge commands executed: `0`",
        "- target trials executed: `0`",
        "",
    ]
    for workspace in packet["workspaces"]:
        lines.extend([
            f"## Workspace `{workspace['workspace']}`",
            "",
            f"- manifest: `{workspace['manifest_path']}`",
            f"- status: `{workspace['status']}`",
            f"- readiness: `{workspace['readiness_status']}`",
            f"- checks: `{workspace['check_count']}`",
            f"- blocking checks: `{workspace['blocking_check_count']}`",
            "",
            "### Blocking Checks",
            "",
        ])
        blocking = [check for check in workspace["checks"] if check["status"] == "fail"]
        if blocking:
            lines.extend(f"- `{check['id']}` ({check['severity']}): {check['detail']}" for check in blocking)
        else:
            lines.append("- none")
        lines.extend(["", "### Execution Steps", ""])
        for step in workspace["execution_steps"]:
            lines.extend([
                f"#### {step['id']}",
                "",
                f"```bash\n{step['command']}\n```",
                "",
                f"- status: `{step['status']}`",
                f"- required: `{str(step['required']).lower()}`",
                "",
            ])
    lines.extend(["## Proof Boundary", "", str(packet["proof_boundary"]), ""])
    return "\n".join(lines)


def write_outputs(out_dir: Path, packet: dict[str, Any]) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / "foundry_v1_7_trial_executor_dry_run.json"
    out_md = out_dir / "foundry_v1_7_trial_executor_dry_run.md"
    out_json.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(packet), encoding="utf-8")
    return out_json, out_md


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."), help="Root to scan for generated v1.7 trial manifests.")
    parser.add_argument("--workspace", action="append", type=Path, help="Explicit workspace to validate; may be repeated.")
    parser.add_argument("--manifest", action="append", type=Path, help="Explicit manifest path to validate; may be repeated.")
    parser.add_argument("--target-bin", type=Path, help="Optional isolated v1.7 bin directory to validate without executing tools.")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="Output directory for dry-run artifacts.")
    parser.add_argument("--strict-exit", action="store_true", help="Exit 2 when dry-run checks are blocked.")
    parser.add_argument("--print-json", action="store_true", help="Print the dry-run packet JSON to stdout.")
    args = parser.parse_args(argv)

    root = args.root.expanduser().resolve()
    if not root.is_dir():
        raise SystemExit(f"[foundry-v17-trial-executor] ERR root not found: {root}")
    manifests: list[Path] = []
    if args.manifest:
        manifests.extend(path.expanduser().resolve() for path in args.manifest)
    if args.workspace:
        manifests.extend((ws.expanduser().resolve() / ".auditooor" / MANIFEST_NAME) for ws in args.workspace)
    if not manifests:
        manifests = _discover_manifests(root)
    missing = [path for path in manifests if not path.is_file()]
    if missing:
        raise SystemExit("[foundry-v17-trial-executor] ERR missing manifest(s): " + ", ".join(str(path) for path in missing))
    target_bin = args.target_bin.expanduser().resolve() if args.target_bin else None
    if target_bin is not None and not target_bin.is_dir():
        raise SystemExit(f"[foundry-v17-trial-executor] ERR target bin not found: {target_bin}")

    packet = build_packet(root, manifests, target_bin)
    out_json, out_md = write_outputs(args.out_dir.expanduser().resolve(), packet)
    if args.print_json:
        print(json.dumps(packet, indent=2, sort_keys=True))
    print(
        "[foundry-v17-trial-executor] OK "
        f"status={packet['status']} workspaces={packet['workspace_count']} "
        f"checks={packet['check_count']} blocked={packet['blocking_check_count']} "
        f"json={out_json} md={out_md}",
        file=sys.stderr,
    )
    if args.strict_exit and packet["status"] != "pass":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
