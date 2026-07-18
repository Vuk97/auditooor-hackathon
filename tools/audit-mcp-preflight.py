#!/usr/bin/env python3
"""Fail-closed MCP session-token preflight for audit entrypoints.

This is intentionally a thin wrapper over ``auditooor_mcp_token.verify_token``.
It does not issue tokens, refresh MCP context, or infer audit readiness.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from auditooor_mcp_token import verify_token


SCHEMA = "auditooor.audit_mcp_preflight.v1"
TOKEN_ENV = "AUDITOOOR_MCP_SESSION_TOKEN"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def payload_summary(payload: dict[str, Any] | None) -> dict[str, Any]:
    if not payload:
        return {}
    exp = payload.get("exp")
    seconds_remaining: int | None = None
    if isinstance(exp, int):
        seconds_remaining = max(0, exp - int(time.time()))
    return {
        "sid": payload.get("sid", ""),
        "owner": payload.get("owner", ""),
        "workspace": payload.get("ws", ""),
        "scope": list(payload.get("scope") or []),
        "expires_at": exp,
        "seconds_remaining": seconds_remaining,
    }


def build_report(
    workspace: Path,
    *,
    token: str,
    required_scope: str = "read",
    require_recent_recall: bool = True,
) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at_utc": utc_now(),
        "workspace_path": str(workspace),
        "status": "fail",
        "ok": False,
        "token_env": TOKEN_ENV,
        "token_present": bool(token),
        "required_scope": required_scope,
        "require_recent_recall": require_recent_recall,
        "payload": {},
        "error": "",
        "next_commands": [],
        "privacy_guards": {
            "token_redacted": True,
            "workspace_scoped": True,
            "does_not_issue_token": True,
            "does_not_refresh_recall": True,
        },
    }

    if not workspace.is_dir():
        report["error"] = f"workspace_not_found: {workspace}"
        return report

    if not token:
        report["error"] = f"{TOKEN_ENV} missing"
        workspace_arg = shlex.quote(str(workspace))
        scope_arg = shlex.quote(required_scope)
        report["next_commands"] = [
            f"bash tools/auditooor-session-start.sh {workspace_arg}",
            f"export {TOKEN_ENV}=$(python3 tools/auditooor_mcp_token.py issue --workspace {workspace_arg} --scope {scope_arg})",
        ]
        return report

    old_ws_root = os.environ.get("AUDITOOOR_WS_ROOT")
    os.environ["AUDITOOOR_WS_ROOT"] = str(workspace)
    try:
        valid, err, payload = verify_token(
            token,
            require_scope=required_scope,
            require_workspace=str(workspace),
            require_recent_recall=require_recent_recall,
        )
    finally:
        if old_ws_root is None:
            os.environ.pop("AUDITOOOR_WS_ROOT", None)
        else:
            os.environ["AUDITOOOR_WS_ROOT"] = old_ws_root

    report["payload"] = payload_summary(payload)
    if not valid:
        report["error"] = err or "token verification failed"
        workspace_arg = shlex.quote(str(workspace))
        scope_arg = shlex.quote(required_scope)
        if require_recent_recall and "recall freshness" in report["error"]:
            report["next_commands"] = [f"bash tools/auditooor-session-start.sh {workspace_arg}"]
        else:
            report["next_commands"] = [
                f"export {TOKEN_ENV}=$(python3 tools/auditooor_mcp_token.py issue --workspace {workspace_arg} --scope {scope_arg})"
            ]
        return report

    report["status"] = "pass"
    report["ok"] = True
    return report


def render_text(report: dict[str, Any]) -> str:
    lines = [
        f"audit MCP preflight: {report['status']}",
        f"workspace: {report['workspace_path']}",
        f"token_present: {str(report['token_present']).lower()}",
        f"required_scope: {report['required_scope']}",
        f"require_recent_recall: {str(report['require_recent_recall']).lower()}",
    ]
    payload = report.get("payload") or {}
    if payload:
        lines.append(f"token_owner: {payload.get('owner', '')}")
        lines.append(f"token_seconds_remaining: {payload.get('seconds_remaining', '')}")
    if report.get("error"):
        lines.append(f"error: {report['error']}")
    if report.get("next_commands"):
        lines.append("next_commands:")
        lines.extend(f"  {cmd}" for cmd in report["next_commands"])
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify a workspace-bound MCP session token before audit work.")
    parser.add_argument("--workspace", required=True, type=Path, help="Audit workspace path.")
    parser.add_argument("--scope", default="read", help="Required token scope. Default: read.")
    parser.add_argument("--token", default=None, help=f"Token override. Defaults to ${TOKEN_ENV}.")
    parser.add_argument(
        "--require-recent-recall",
        action="store_true",
        help="Also require a fresh .auditooor/last_mcp_recall.json sentinel.",
    )
    parser.add_argument("--json", action="store_true", help="Emit a JSON envelope.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    token = args.token if args.token is not None else os.environ.get(TOKEN_ENV, "")
    report = build_report(
        args.workspace,
        token=token,
        required_scope=args.scope,
        require_recent_recall=args.require_recent_recall,
    )
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(render_text(report))
    if report["ok"]:
        return 0
    if str(report.get("error", "")).startswith("workspace_not_found:"):
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
