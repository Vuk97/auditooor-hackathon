#!/usr/bin/env python3
"""pre-mcp-route-check.py — recommend the right MCP recall pack BEFORE
a worker calls one directly.

This is a thin advisory wrapper around ``vault_route`` (vault-mcp-server.py).
Workers (and Codex agents) should call this first; calling a specific pack
manually is allowed but discouraged when the recommendation differs.

Usage:
    python3 tools/pre-mcp-route-check.py \
        --workspace-path /path/to/workspace \
        [--intent resume|exploit|harness|gap|auto] \
        [--task-keywords harness,replay,blocker] \
        [--recent-artifacts foo.t.sol,bar_test.go] \
        [--json]

Exits 0 with the recommendation. Exits 2 on bad input. Exits 3 if the
underlying ``vault_route`` call returned an error structure (so CI / hooks
can fail loud). Stdlib-only.

Cross-link: see ``tools/vault-mcp-server.py`` (vault_route) and
``docs/next-loop/mcp_route_design_2026-05-06.md``.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _strip_banner(stdout: str) -> str:
    return "\n".join(
        line for line in stdout.splitlines() if not line.startswith("[vault-mcp-server]")
    ).strip()


def _call_router(args_payload: dict) -> tuple[int, dict]:
    proc = subprocess.run(
        [
            sys.executable,
            str(SERVER),
            "--call",
            "vault_route",
            "--args",
            json.dumps(args_payload),
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return proc.returncode, {
            "error": "router_subprocess_failed",
            "stderr": proc.stderr[-1000:],
            "stdout": proc.stdout[-1000:],
        }
    body = _strip_banner(proc.stdout)
    if not body:
        return 1, {"error": "empty_router_payload", "stderr": proc.stderr[-1000:]}
    try:
        return 0, json.loads(body)
    except json.JSONDecodeError as exc:
        return 1, {"error": "router_payload_not_json", "message": str(exc), "body": body[:1000]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-path", required=True)
    parser.add_argument("--intent", default=None, choices=["resume", "exploit", "harness", "gap", "auto", None])
    parser.add_argument("--task-keywords", default=None, help="Comma-separated keyword list.")
    parser.add_argument("--recent-artifacts", default=None, help="Comma-separated artifact path list.")
    parser.add_argument("--json", action="store_true", help="Emit full JSON payload (default: summary line).")
    args = parser.parse_args(argv)

    payload: dict = {"workspace_path": args.workspace_path}
    if args.intent:
        payload["intent"] = args.intent
    keywords = _split_csv(args.task_keywords)
    if keywords:
        payload["task_keywords"] = keywords
    artifacts = _split_csv(args.recent_artifacts)
    if artifacts:
        payload["recent_artifacts"] = artifacts

    rc, result = _call_router(payload)
    if rc != 0:
        print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
        return 2
    if "error" in result:
        print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        routed = result.get("routed_pack", "?")
        reasoning = result.get("reasoning", "")
        print(f"recommended_pack={routed} reason={reasoning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
