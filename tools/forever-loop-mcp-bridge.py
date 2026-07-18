#!/usr/bin/env python3
"""forever-loop-mcp-bridge.py — MCP session-token bridge for forever-mode / cron loops.

PR #658 Lane 7 — Worker-B1 deliverable.

Background
----------
Q18 (MCP harness review 2026-05-09): overnight / forever-mode loops need a way to
acquire `mcp_session_token` without interactive prompts. Resolution: issue a long-TTL
service-account token once (prime), persist it at mode 0600, then let each loop
iteration `export-env` it into the subprocess environment.

Subcommands
-----------
prime --workspace <ws> [--ttl-hours N]
    Issues a 24h (default) service-account token via auditooor_mcp_token.issue_token(),
    writes it to <ws>/.auditooor/forever_loop_mcp_token at mode 0600.
    Stdout: single line "[forever-loop-mcp-bridge] primed ttl=Nh hash=<8hex>"
    Idempotent: re-primes if existing token is missing or within 1h of expiry.

export-env --workspace <ws>
    Reads primed token, checks it is present and not expired.
    Emits: export AUDITOOOR_MCP_SESSION_TOKEN=<token>
    Suitable for: eval "$(python3 tools/forever-loop-mcp-bridge.py export-env --workspace .)"
    Exits 1 (without output) if file is missing or token is expired.

Security notes
--------------
- Raw token is NEVER logged; only first 8 hex chars of sha256(token) appear on stdout.
- Token file mode 0600; parent dir created with 0o700 if absent.
- Stdlib only (no external deps).
- All paths via pathlib.Path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys
import time
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TOKEN_RELATIVE = ".auditooor/forever_loop_mcp_token"
TOKEN_DIR_MODE = 0o700
TOKEN_FILE_MODE = 0o600
DEFAULT_TTL_HOURS = 24
RENEW_HEADROOM_SECONDS = 3600  # re-prime if token expires within 1h


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _token_path(workspace: pathlib.Path) -> pathlib.Path:
    return workspace.resolve() / TOKEN_RELATIVE


def _token_hash8(token: str) -> str:
    """Return first 8 hex chars of sha256(token) — safe to log."""
    return hashlib.sha256(token.encode()).hexdigest()[:8]


def _read_token_file(token_path: pathlib.Path) -> Optional[str]:
    """Read token from file. Returns None if missing or unreadable."""
    try:
        return token_path.read_text().strip()
    except OSError:
        return None


def _load_auditooor_mcp_token():
    """Import auditooor_mcp_token from tools/ without polluting sys.path permanently."""
    import importlib.util
    here = pathlib.Path(__file__).parent
    spec = importlib.util.spec_from_file_location(
        "auditooor_mcp_token", here / "auditooor_mcp_token.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _token_expiry(token: str) -> Optional[int]:
    """Decode token payload and return exp field, or None on failure."""
    try:
        mod = _load_auditooor_mcp_token()
        payload = mod.decode_token(token)
        if payload is None:
            return None
        return int(payload.get("exp", 0))
    except Exception:
        return None


def _token_is_fresh(token: str) -> bool:
    """Return True if token exists and won't expire within RENEW_HEADROOM_SECONDS."""
    exp = _token_expiry(token)
    if exp is None:
        return False
    return int(time.time()) + RENEW_HEADROOM_SECONDS < exp


# ---------------------------------------------------------------------------
# Subcommand: prime
# ---------------------------------------------------------------------------

def cmd_prime(workspace: pathlib.Path, ttl_hours: int) -> int:
    """Issue a long-TTL service-account token and write to workspace token file."""
    token_path = _token_path(workspace)

    # Idempotency: skip if existing token is still fresh
    existing = _read_token_file(token_path)
    if existing and _token_is_fresh(existing):
        h = _token_hash8(existing)
        exp = _token_expiry(existing)
        remaining_h = max(0, (exp - int(time.time()))) // 3600
        print(f"[forever-loop-mcp-bridge] already primed ttl={remaining_h}h hash={h} (skipping re-issue)")
        return 0

    ttl_seconds = ttl_hours * 3600
    try:
        mod = _load_auditooor_mcp_token()
        token, _payload = mod.issue_token(
            workspace_path=str(workspace.resolve()),
            ttl_seconds=ttl_seconds,
            owner="service-account",
            scope=["read", "write", "remember"],
            log=True,
        )
    except Exception as exc:
        sys.stderr.write(f"[forever-loop-mcp-bridge] prime failed: {exc}\n")
        return 1

    # Write token at mode 0600
    token_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(token_path.parent, TOKEN_DIR_MODE)
    except OSError:
        pass  # not all filesystems support chmod

    # Atomic write: tmp file then rename
    tmp_path = token_path.with_suffix(".tmp")
    try:
        tmp_path.write_text(token)
        os.chmod(tmp_path, TOKEN_FILE_MODE)
        tmp_path.rename(token_path)
    except OSError as exc:
        sys.stderr.write(f"[forever-loop-mcp-bridge] write failed: {exc}\n")
        tmp_path.unlink(missing_ok=True)
        return 1

    h = _token_hash8(token)
    print(f"[forever-loop-mcp-bridge] primed ttl={ttl_hours}h hash={h}")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: export-env
# ---------------------------------------------------------------------------

def cmd_export_env(workspace: pathlib.Path) -> int:
    """Emit export statement for AUDITOOOR_MCP_SESSION_TOKEN if token is valid."""
    token_path = _token_path(workspace)
    token = _read_token_file(token_path)

    if not token:
        sys.stderr.write(
            f"[forever-loop-mcp-bridge] export-env: no token at {token_path} — "
            "run `prime` first\n"
        )
        return 1

    if not _token_is_fresh(token):
        exp = _token_expiry(token)
        now = int(time.time())
        if exp is not None and now > exp:
            sys.stderr.write(
                f"[forever-loop-mcp-bridge] export-env: token expired "
                f"{now - exp}s ago — run `prime` to renew\n"
            )
        else:
            sys.stderr.write(
                "[forever-loop-mcp-bridge] export-env: token expires within "
                f"{RENEW_HEADROOM_SECONDS}s — run `prime` to renew\n"
            )
        return 1

    # Emit shell-safe export (token is base64url + dots, no shell special chars)
    print(f"export AUDITOOOR_MCP_SESSION_TOKEN={token}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="MCP session-token bridge for forever-mode / cron loops",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_prime = sub.add_parser(
        "prime",
        help="issue a long-TTL service-account token and persist to workspace",
    )
    p_prime.add_argument(
        "--workspace", required=True, type=pathlib.Path,
        help="auditooor workspace root (must exist)",
    )
    p_prime.add_argument(
        "--ttl-hours", type=int, default=DEFAULT_TTL_HOURS,
        help=f"token TTL in hours (default: {DEFAULT_TTL_HOURS})",
    )

    p_export = sub.add_parser(
        "export-env",
        help="emit export AUDITOOOR_MCP_SESSION_TOKEN=... for eval",
    )
    p_export.add_argument(
        "--workspace", required=True, type=pathlib.Path,
        help="auditooor workspace root",
    )

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    workspace = pathlib.Path(args.workspace).resolve()
    if not workspace.is_dir():
        sys.stderr.write(f"[forever-loop-mcp-bridge] workspace not found: {workspace}\n")
        return 1

    if args.cmd == "prime":
        return cmd_prime(workspace, args.ttl_hours)
    if args.cmd == "export-env":
        return cmd_export_env(workspace)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
