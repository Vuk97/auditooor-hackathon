#!/usr/bin/env python3
"""Read-only Phase A control-plane readiness preflight.

Phase A composes existing bounded MCP surfaces without editing workspace state:

* ``tools/vault-mcp-server.py --self-test``
* ``vault_brain_prime_context``
* ``vault_high_impact_execution_bridge_context``

By default the tool is advisory/read-only and exits 0 with a structured
``status``. Pass ``--strict`` when using it as a dispatch gate; strict mode
returns non-zero unless all required control-plane evidence is present.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.control_plane_ready_preflight.v1"
SOURCE_PLAN = "reports/control_plane_ready_preflight_plan_2026-05-17.md"
SELF_TEST_PASS = "SELF-TEST PASS"
FINALIZATION_MANIFEST_RELATIVE_PATH = Path(".auditooor/finalization/current_manifest.json")


def utc_now() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def trim(text: str | None, limit: int = 2000) -> str:
    if not text:
        return ""
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


def parse_mcp_json(stdout: str) -> dict[str, Any]:
    """Parse MCP CLI JSON while tolerating banner lines."""
    lines = [line for line in stdout.splitlines() if not line.startswith("[vault-mcp-server]")]
    body = "\n".join(lines).strip()
    if not body:
        raise ValueError("empty MCP response")
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise ValueError("MCP response was not a JSON object")
    return payload


def run_command(command: list[str], repo_root: Path, timeout: float) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            command,
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "exit_code": None,
            "stdout": trim(exc.stdout if isinstance(exc.stdout, str) else ""),
            "stderr": trim(exc.stderr if isinstance(exc.stderr, str) else ""),
            "error": f"timed out after {timeout:g}s",
        }
    except OSError as exc:
        return {
            "ok": False,
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "error": str(exc),
        }
    return {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
        "error": "",
    }


def mcp_call(callable_name: str, workspace: Path, repo_root: Path, timeout: float, *, limit: int = 3) -> dict[str, Any]:
    args = json.dumps({"workspace_path": str(workspace), "limit": limit}, sort_keys=True)
    command = ["python3", "tools/vault-mcp-server.py", "--call", callable_name, "--args", args]
    result = run_command(command, repo_root, timeout)
    envelope: dict[str, Any] = {
        "callable": callable_name,
        "command": command[:3] + ["<callable>", "--args", "<workspace-scoped-json>"],
        "exit_code": result["exit_code"],
    }
    if not result["ok"]:
        envelope.update(
            {
                "status": "degraded",
                "degraded": True,
                "error": result.get("error") or "mcp_call_failed",
                "stdout": trim(result["stdout"]),
                "stderr": trim(result["stderr"]),
            }
        )
        return envelope
    try:
        payload = parse_mcp_json(result["stdout"])
    except (json.JSONDecodeError, ValueError) as exc:
        envelope.update(
            {
                "status": "degraded",
                "degraded": True,
                "error": f"invalid_mcp_json: {exc}",
                "stdout": trim(result["stdout"]),
                "stderr": trim(result["stderr"]),
            }
        )
        return envelope
    envelope.update({"status": "loaded", "degraded": bool(payload.get("degraded")), "payload": payload})
    return envelope


def check_mcp_self_test(repo_root: Path, timeout: float) -> dict[str, Any]:
    command = ["python3", "tools/vault-mcp-server.py", "--self-test"]
    result = run_command(command, repo_root, timeout)
    combined = "\n".join(part for part in [result["stdout"], result["stderr"]] if part)
    passed = bool(result["ok"] and SELF_TEST_PASS in combined)
    status = "pass" if passed else "fail"
    check: dict[str, Any] = {
        "status": status,
        "exit_code": result["exit_code"],
        "pass_marker_found": SELF_TEST_PASS in combined,
        "command": command,
    }
    if not passed:
        check["error"] = result.get("error") or "self_test_failed_or_pass_marker_missing"
        check["stdout"] = trim(result["stdout"])
        check["stderr"] = trim(result["stderr"])
    return check


def check_finalization_manifest(workspace: Path, repo_root: Path, timeout: float) -> dict[str, Any]:
    manifest_path = (workspace / FINALIZATION_MANIFEST_RELATIVE_PATH).resolve()
    check: dict[str, Any] = {
        "manifest_path": str(manifest_path),
        "advisory_only": True,
        "proof_readiness": "incomplete",
        "command": [
            "python3",
            "tools/finalization-manifest.py",
            "read",
            "--manifest",
            str(manifest_path),
            "--json",
        ],
    }
    if not manifest_path.is_file():
        check.update(
            {
                "status": "missing",
                "warning_level": "warn",
                "passed": False,
                "error": "manifest_not_found",
            }
        )
        return check

    result = run_command(check["command"], repo_root, timeout)
    if not result["stdout"].strip():
        check.update(
            {
                "status": "degraded",
                "warning_level": "warn",
                "passed": False,
                "degraded": True,
                "error": result.get("error") or "finalization_manifest_read_failed",
                "stdout": trim(result["stdout"]),
                "stderr": trim(result["stderr"]),
            }
        )
        return check

    try:
        payload = json.loads(result["stdout"])
    except json.JSONDecodeError as exc:
        check.update(
            {
                "status": "degraded",
                "warning_level": "warn",
                "passed": False,
                "degraded": True,
                "error": f"invalid_finalization_manifest_json: {exc}",
                "stdout": trim(result["stdout"]),
                "stderr": trim(result["stderr"]),
            }
        )
        return check

    validation_status = str(payload.get("status") or "")
    passed = bool(payload.get("passed"))
    if validation_status == "pass" and passed:
        check.update(
            {
                "status": "pass",
                "warning_level": "info",
                "passed": True,
                "proof_readiness": "pass",
                "validation_status": validation_status,
                "errors": [],
            }
        )
        return check

    check.update(
        {
            "status": "fail",
            "warning_level": "warn",
            "passed": False,
            "validation_status": validation_status or "unknown",
            "errors": list(payload.get("errors") or []),
            "stdout": "" if result["ok"] else trim(result["stdout"]),
            "stderr": trim(result["stderr"]),
        }
    )
    if validation_status == "malformed_input":
        check["error"] = "manifest_malformed_input"
    elif not result["ok"] and result.get("error"):
        check["error"] = result["error"]
    return check


def classify_brain_prime(call_result: dict[str, Any]) -> dict[str, Any]:
    if call_result.get("status") == "degraded" and "payload" not in call_result:
        return {
            "status": "degraded",
            "dispatch_ready": False,
            "degraded": True,
            "error": call_result.get("error", "mcp_call_failed"),
        }
    payload = dict(call_result.get("payload") or {})
    error = str(payload.get("error") or payload.get("degraded_reason") or "")
    receipt_found = bool(payload.get("receipt_found"))
    dispatch_ready = bool(payload.get("dispatch_ready"))
    if dispatch_ready:
        status = "ready"
    elif not receipt_found or error in {"receipt_not_found", "workspace_not_found"}:
        status = "missing"
    elif payload.get("degraded"):
        status = "degraded"
    else:
        status = "blocked"
    return {
        "status": status,
        "dispatch_ready": dispatch_ready,
        "degraded": bool(payload.get("degraded")),
        "receipt_found": receipt_found,
        "integrity": payload.get("integrity", {}),
        "lanes_returned": payload.get("lanes_returned", 0),
        "context_pack_id": payload.get("context_pack_id", ""),
        "error": error,
        "source_refs": payload.get("source_refs", []),
    }


def classify_high_impact_bridge(call_result: dict[str, Any]) -> dict[str, Any]:
    if call_result.get("status") == "degraded" and "payload" not in call_result:
        return {
            "status": "degraded",
            "promotion_allowed": False,
            "submission_posture": "NOT_SUBMIT_READY",
            "degraded": True,
            "error": call_result.get("error", "mcp_call_failed"),
        }
    payload = dict(call_result.get("payload") or {})
    error = str(payload.get("error") or payload.get("degraded_reason") or "")
    if payload.get("degraded") and error in {
        "high_impact_execution_bridge_json_missing",
        "workspace_not_found",
    }:
        status = "missing"
    elif payload.get("degraded"):
        status = "degraded"
    else:
        status = "available"
    summary = dict(payload.get("summary") or {})
    return {
        "status": status,
        "promotion_allowed": bool(payload.get("promotion_allowed")),
        "submission_posture": payload.get("submission_posture", "NOT_SUBMIT_READY"),
        "degraded": bool(payload.get("degraded")),
        "advisory_only": bool(payload.get("advisory_only", True)),
        "rows_returned": summary.get("rows_returned", 0),
        "runnable_harness_rows": summary.get("runnable_harness_rows", 0),
        "freshness": payload.get("freshness", {}),
        "context_pack_id": payload.get("context_pack_id", ""),
        "error": error,
        "source_refs": payload.get("source_refs", []),
    }


def build_report(workspace: Path, repo_root: Path, timeout: float, *, strict: bool = False) -> dict[str, Any]:
    repo_root = repo_root.expanduser().resolve()
    workspace = workspace.expanduser().resolve()

    mcp_self_test = check_mcp_self_test(repo_root, timeout)
    brain_prime = classify_brain_prime(
        mcp_call("vault_brain_prime_context", workspace, repo_root, timeout, limit=3)
    )
    high_impact_bridge = classify_high_impact_bridge(
        mcp_call("vault_high_impact_execution_bridge_context", workspace, repo_root, timeout, limit=3)
    )
    finalization_manifest = check_finalization_manifest(workspace, repo_root, timeout)

    checks = {
        "mcp_self_test": mcp_self_test,
        "brain_prime": brain_prime,
        "high_impact_bridge": high_impact_bridge,
        "finalization_manifest": finalization_manifest,
    }
    blockers: list[str] = []
    if mcp_self_test["status"] != "pass":
        blockers.append("mcp_self_test_failed")
    if brain_prime["status"] != "ready":
        blockers.append(f"brain_prime_{brain_prime['status']}")
    if high_impact_bridge["status"] != "available":
        blockers.append(f"high_impact_bridge_{high_impact_bridge['status']}")
    if strict and finalization_manifest["status"] != "pass":
        blockers.append(f"finalization_manifest_{finalization_manifest['status']}")

    any_degraded = any(bool(check.get("degraded")) for check in checks.values())
    status = "ready" if not blockers else ("degraded" if any_degraded else "blocked")
    dispatch_ready = status == "ready"
    proof_readiness = finalization_manifest["proof_readiness"]
    strict_ready = bool(dispatch_ready and (not strict or finalization_manifest["status"] == "pass"))

    source_refs = [SOURCE_PLAN, "tools/vault-mcp-server.py"]
    for check in (brain_prime, high_impact_bridge):
        for ref in check.get("source_refs", []):
            if isinstance(ref, str) and ref and ref not in source_refs:
                source_refs.append(ref)

    return {
        "schema": SCHEMA,
        "generated_at_utc": utc_now(),
        "workspace_path": str(workspace),
        "repo_root": str(repo_root),
        "status": status,
        "dispatch_ready": dispatch_ready,
        "strict_mode": strict,
        "strict_ready": strict_ready,
        "proof_readiness": proof_readiness,
        "submission_readiness": "NOT_SUBMIT_READY",
        "checks": checks,
        "blockers": blockers,
        "next_commands": next_commands(workspace, checks),
        "source_refs": source_refs,
        "privacy_guards": {
            "workspace_scoped": True,
            "raw_doc_dump_blocked": True,
            "advisory_freshness_not_proof": True,
            "read_only_default": True,
            "strict_mode_fail_closed": strict,
        },
    }


def next_commands(workspace: Path, checks: dict[str, dict[str, Any]]) -> list[str]:
    commands: list[str] = []
    if checks["mcp_self_test"]["status"] != "pass":
        commands.append("make vault-mcp-self-test")
    if checks["brain_prime"]["status"] != "ready":
        commands.append(f"make brain-prime WS={workspace}")
    if checks["high_impact_bridge"]["status"] != "available":
        commands.append(f"make high-impact-execution-bridge WS={workspace} JSON=1")
    if checks["finalization_manifest"]["status"] != "pass":
        commands.append(
            "python3 tools/finalization-manifest.py read "
            f"--manifest {workspace / FINALIZATION_MANIFEST_RELATIVE_PATH} --json"
        )
    return commands


def render_text(report: dict[str, Any]) -> str:
    lines = [
        f"Control-plane ready Phase A: {report['status']}",
        f"Workspace: {report['workspace_path']}",
        f"Dispatch ready: {str(report['dispatch_ready']).lower()}",
        f"Strict mode: {str(report.get('strict_mode', False)).lower()}",
        f"Strict ready: {str(report.get('strict_ready', report['dispatch_ready'])).lower()}",
        f"MCP self-test: {report['checks']['mcp_self_test']['status']}",
        f"Brain-prime: {report['checks']['brain_prime']['status']}",
        f"High-impact bridge: {report['checks']['high_impact_bridge']['status']}",
        f"Finalization manifest: {report['checks']['finalization_manifest']['status']}",
        f"Proof readiness: {report['proof_readiness']}",
    ]
    if report["blockers"]:
        lines.append("Blockers: " + ", ".join(report["blockers"]))
    if report["next_commands"]:
        lines.append("Next commands:")
        lines.extend(f"  {command}" for command in report["next_commands"])
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only Phase A control-plane-ready preflight.")
    parser.add_argument("--workspace", required=True, type=Path, help="Audit workspace path.")
    parser.add_argument("--repo-root", type=Path, default=default_repo_root(), help="auditooor-mcp repo root.")
    parser.add_argument("--timeout", type=float, default=60.0, help="Per MCP subprocess timeout in seconds.")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero unless dispatch/control-plane evidence is ready.")
    parser.add_argument("--json", action="store_true", help="Print the full JSON envelope.")
    parser.add_argument("--out", type=Path, help="Optional path to write the JSON envelope. No workspace write occurs unless set.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    report = build_report(args.workspace, args.repo_root, args.timeout, strict=args.strict)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(render_text(report))
    if args.strict and not report["strict_ready"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
