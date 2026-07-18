"""auditooor_mcp_token — per-session HMAC-signed MCP receipt tokens.

Lane 7 of MCP harness review (PR #658) commit 2. Provides the primitive that
all later commits' mutating callables consume.

Wave-6 E-2: added freshness gate via require_recent_recall kwarg and
--require-recent-recall CLI flag. Closes the 4h stale-token bypass window
documented in sub-report 04 F4.

A token is a base64url-encoded JSON payload + HMAC-SHA256 signature, format:
    <b64-payload>.<b64-signature>

Payload fields:
    v       version (currently 1)
    sid     session UUID
    ws      workspace_path (absolute)
    owner   issuer agent (claude | codex | kimi | minimax | service-account)
    iat     issued_at (unix timestamp)
    exp     expires_at (unix timestamp)
    scope   list of allowed actions (e.g. ['read', 'write', 'remember'])

Secret lives at $AUDITOOOR_MCP_SECRET env var, falling back to
~/.auditooor/mcp_secret (auto-generated, mode 0600). Default TTL 4h.

Background-loop / forever-mode usage: `--owner service-account --ttl 86400`
issues a 24h token for cron-spawned processes (per Q18 operator decision).

Public API:
    issue_token(workspace_path, ttl_seconds=14400, owner="claude", scope=None)
    verify_token(token, *, require_scope=None, require_recent_recall=False) -> (is_valid, error, payload)
    refresh_token(old_token, ttl_seconds=14400) -> new_token (re-issues if old still valid)

CLI:
    python3 tools/auditooor_mcp_token.py issue [--workspace P] [--owner O] [--ttl S] [--scope S]
    python3 tools/auditooor_mcp_token.py verify <token> [--require-recent-recall]
    python3 tools/auditooor_mcp_token.py info <token>     # decodes without verification

Freshness gate (Wave-6 E-2):
    When verify_token() is called with require_recent_recall=True, the function
    additionally checks that .auditooor/last_mcp_recall.json exists in the
    workspace root and that its recall_ts field is within AUDITOOOR_RECALL_MAX_AGE_S
    seconds (default 1800) of the current time. If either check fails, False is
    returned and an audit entry is appended to .auditooor/bypass_log.jsonl.

    Workspace root resolution order:
      1. AUDITOOOR_WS_ROOT env var
      2. payload["ws"] field of the token being verified
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import sys
import time
import uuid
from typing import Optional, Tuple

TOKEN_VERSION = 1
DEFAULT_TTL_SECONDS = 4 * 3600  # 4 hours
SERVICE_ACCOUNT_TTL_SECONDS = 24 * 3600  # 24 hours for background loops
DEFAULT_SCOPE = ["read", "write", "remember"]
SECRET_ENV = "AUDITOOOR_MCP_SECRET"
SECRET_FILE = pathlib.Path.home() / ".auditooor" / "mcp_secret"
TOKEN_LOG_RELATIVE = ".auditooor/mcp_session_tokens.jsonl"
BYPASS_LOG_RELATIVE = ".auditooor/bypass_log.jsonl"
MCP_RECALL_SENTINEL = ".auditooor/last_mcp_recall.json"
# Default max age for MCP recall freshness check (Wave-6 E-2). Override via
# AUDITOOOR_RECALL_MAX_AGE_S env var in both shell wrappers and Python callers.
DEFAULT_RECALL_MAX_AGE_S = 1800  # 30 minutes
ALLOWED_OWNERS = {
    "claude", "codex", "kimi", "minimax", "anthropic-direct",
    "orchestrator", "operator", "service-account",
}


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _get_secret() -> bytes:
    env = os.environ.get(SECRET_ENV)
    if env:
        return env.encode()
    if not SECRET_FILE.is_file():
        SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        new_secret = secrets.token_hex(32)
        SECRET_FILE.write_text(new_secret)
        try:
            os.chmod(SECRET_FILE, 0o600)
        except OSError:
            pass  # not all filesystems support chmod
    return SECRET_FILE.read_text().strip().encode()


def issue_token(
    workspace_path: str,
    *,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    owner: str = "claude",
    scope: Optional[list] = None,
    log: bool = True,
) -> Tuple[str, dict]:
    """Issues a fresh session token. Returns (token_str, payload_dict).

    If ``log=True`` (default), appends a redacted record to
    {workspace_path}/.auditooor/mcp_session_tokens.jsonl.
    """
    if owner not in ALLOWED_OWNERS:
        raise ValueError(f"owner must be one of {sorted(ALLOWED_OWNERS)}, got {owner!r}")
    if scope is None:
        scope = DEFAULT_SCOPE
    issued_at = int(time.time())
    expires_at = issued_at + int(ttl_seconds)
    payload = {
        "v": TOKEN_VERSION,
        "sid": str(uuid.uuid4()),
        "ws": str(pathlib.Path(workspace_path).resolve()) if workspace_path else "",
        "owner": owner,
        "iat": issued_at,
        "exp": expires_at,
        "scope": list(scope),
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(_get_secret(), payload_bytes, hashlib.sha256).digest()
    token = _b64e(payload_bytes) + "." + _b64e(sig)

    if log and workspace_path:
        log_path = pathlib.Path(workspace_path) / TOKEN_LOG_RELATIVE
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            redacted = {
                "schema": "auditooor.mcp_session_token.v1",
                "sid": payload["sid"],
                "ws": payload["ws"],
                "owner": payload["owner"],
                "iat": payload["iat"],
                "exp": payload["exp"],
                "scope": payload["scope"],
                "token_short": token[:24] + "...",
            }
            with log_path.open("a") as fh:
                fh.write(json.dumps(redacted) + "\n")
        except OSError as exc:
            sys.stderr.write(f"[mcp-token] log write failed: {exc}\n")

    return token, payload


def _check_recall_freshness(
    workspace_root: Optional[str],
    *,
    max_age_s: Optional[int] = None,
    bypass_log_path: Optional[pathlib.Path] = None,
) -> Tuple[bool, Optional[str]]:
    """Wave-6 E-2: verify .auditooor/last_mcp_recall.json exists and is fresh.

    Returns (ok, error_message). When ok=False, appends an audit entry to
    bypass_log_path (if provided).

    Args:
        workspace_root: absolute path to workspace; None means skip check.
        max_age_s: override max age; defaults to AUDITOOOR_RECALL_MAX_AGE_S env
                   or DEFAULT_RECALL_MAX_AGE_S (1800 s).
        bypass_log_path: where to append bypass audit entries on failure.
    """
    if workspace_root is None:
        return False, "cannot check recall freshness: no workspace_root resolved"

    if max_age_s is None:
        env_age = os.environ.get("AUDITOOOR_RECALL_MAX_AGE_S")
        max_age_s = int(env_age) if env_age and env_age.isdigit() else DEFAULT_RECALL_MAX_AGE_S

    sentinel = pathlib.Path(workspace_root) / MCP_RECALL_SENTINEL

    def _log_bypass(reason: str, extra: Optional[dict] = None) -> None:
        if bypass_log_path is None:
            return
        try:
            bypass_log_path.parent.mkdir(parents=True, exist_ok=True)
            entry: dict = {
                "ts": time.time(),
                "iso": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "event": "recall_freshness_failure",
                "reason": reason,
                "workspace": str(workspace_root),
            }
            if extra:
                entry.update(extra)
            with bypass_log_path.open("a") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass  # best-effort audit log

    if not sentinel.is_file():
        _log_bypass("no_recall_file")
        return False, (
            f"MCP recall sentinel not found: {sentinel}. "
            "Run: bash tools/auditooor-session-start.sh"
        )

    try:
        recall_data = json.loads(sentinel.read_text())
        recall_ts = float(recall_data.get("recall_ts", 0))
    except Exception as exc:
        _log_bypass("recall_file_parse_error", {"error": str(exc)})
        return False, f"MCP recall sentinel parse error: {exc}"

    age_s = time.time() - recall_ts
    if age_s > max_age_s:
        _log_bypass("recall_stale", {"age_s": round(age_s, 1), "max_age_s": max_age_s})
        return False, (
            f"MCP recall sentinel stale: {round(age_s)}s old (max {max_age_s}s). "
            "Re-run: bash tools/auditooor-session-start.sh"
        )

    return True, None


def verify_token(
    token: str,
    *,
    require_scope: Optional[str] = None,
    require_workspace: Optional[str] = None,
    require_recent_recall: bool = False,
) -> Tuple[bool, Optional[str], Optional[dict]]:
    """Verifies a session token. Returns (is_valid, error_message, payload).

    If ``require_scope`` set, also checks that scope is in payload.scope.
    If ``require_workspace`` set, checks payload.ws matches.
    If ``require_recent_recall`` True (Wave-6 E-2), additionally verifies that
    .auditooor/last_mcp_recall.json exists and is fresh (within
    AUDITOOOR_RECALL_MAX_AGE_S seconds, default 1800). Workspace is resolved
    from AUDITOOOR_WS_ROOT env, then from payload["ws"]. Failure appends an
    audit entry to .auditooor/bypass_log.jsonl in the resolved workspace.
    This check runs AFTER all signature/expiry checks so a forged token cannot
    bypass it.
    """
    if not token or "." not in token:
        return False, "malformed token (missing payload.signature delimiter)", None

    parts = token.rsplit(".", 1)
    if len(parts) != 2:
        return False, "malformed token (split fail)", None
    payload_b64, sig_b64 = parts

    try:
        payload_bytes = _b64d(payload_b64)
        payload = json.loads(payload_bytes.decode())
        sig = _b64d(sig_b64)
    except Exception as exc:
        return False, f"decode error: {exc}", None

    if payload.get("v") != TOKEN_VERSION:
        return False, f"unsupported version {payload.get('v')}", payload

    expected_sig = hmac.new(_get_secret(), payload_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected_sig):
        return False, "signature mismatch", payload

    now = int(time.time())
    if now > payload.get("exp", 0):
        return False, f"expired {now - payload['exp']}s ago", payload

    if require_scope and require_scope not in payload.get("scope", []):
        return False, f"scope {require_scope!r} not in token scope {payload.get('scope')}", payload

    if require_workspace:
        rw = str(pathlib.Path(require_workspace).resolve())
        if payload.get("ws") != rw:
            return False, f"workspace mismatch: token={payload.get('ws')} required={rw}", payload

    if require_recent_recall:
        # Resolve workspace: env override > token payload
        ws_root = os.environ.get("AUDITOOOR_WS_ROOT") or payload.get("ws")
        if ws_root:
            bypass_log = pathlib.Path(ws_root) / BYPASS_LOG_RELATIVE
        else:
            bypass_log = None
        ok, recall_err = _check_recall_freshness(ws_root, bypass_log_path=bypass_log)
        if not ok:
            return False, f"recall freshness check failed: {recall_err}", payload

    return True, None, payload


def refresh_token(old_token: str, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> Optional[str]:
    """If old_token is still valid, issue a fresh token with same scope/owner/ws.

    Returns new token string, or None if old_token is invalid.
    """
    valid, err, payload = verify_token(old_token)
    if not valid or not payload:
        sys.stderr.write(f"[mcp-token] refresh failed: {err}\n")
        return None
    new_token, _ = issue_token(
        workspace_path=payload["ws"],
        ttl_seconds=ttl_seconds,
        owner=payload["owner"],
        scope=payload.get("scope"),
    )
    return new_token


def decode_token(token: str) -> Optional[dict]:
    """Decodes payload WITHOUT verification (for debugging / token inspection)."""
    if not token or "." not in token:
        return None
    payload_b64, _ = token.rsplit(".", 1)
    try:
        return json.loads(_b64d(payload_b64).decode())
    except Exception:
        return None


def _cli():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_iss = sub.add_parser("issue", help="issue a fresh session token")
    p_iss.add_argument("--workspace", default=os.getcwd(), help="workspace path (default: cwd)")
    p_iss.add_argument("--owner", default="claude", choices=sorted(ALLOWED_OWNERS))
    p_iss.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS, help="TTL in seconds (default 14400 = 4h)")
    p_iss.add_argument("--service-account", action="store_true", help="alias for --ttl 86400 --owner service-account")
    p_iss.add_argument("--scope", nargs="*", default=DEFAULT_SCOPE)
    p_iss.add_argument("--no-log", action="store_true", help="do not append to mcp_session_tokens.jsonl")
    p_iss.add_argument("--json", action="store_true", help="emit full JSON record")

    p_ver = sub.add_parser("verify", help="verify a token; exit 0 if valid")
    p_ver.add_argument("token")
    p_ver.add_argument("--require-scope", default=None)
    p_ver.add_argument("--require-workspace", default=None)
    p_ver.add_argument(
        "--require-recent-recall",
        action="store_true",
        default=False,
        help=(
            "Wave-6 E-2: also verify .auditooor/last_mcp_recall.json is fresh "
            "(within AUDITOOOR_RECALL_MAX_AGE_S seconds, default 1800). "
            "Workspace resolved from AUDITOOOR_WS_ROOT env or token payload."
        ),
    )
    p_ver.add_argument("--json", action="store_true")

    p_inf = sub.add_parser("info", help="decode payload (no verification)")
    p_inf.add_argument("token")

    args = parser.parse_args()

    if args.cmd == "issue":
        if args.service_account:
            args.ttl = SERVICE_ACCOUNT_TTL_SECONDS
            args.owner = "service-account"
        token, payload = issue_token(
            workspace_path=args.workspace,
            ttl_seconds=args.ttl,
            owner=args.owner,
            scope=args.scope,
            log=not args.no_log,
        )
        if args.json:
            print(json.dumps({"token": token, "payload": payload}, indent=2))
        else:
            print(token)
        return 0

    if args.cmd == "verify":
        valid, err, payload = verify_token(
            args.token,
            require_scope=args.require_scope,
            require_workspace=args.require_workspace,
            require_recent_recall=args.require_recent_recall,
        )
        result = {"valid": valid, "error": err, "payload": payload}
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"valid={valid} error={err}")
            if payload:
                print(f"payload: owner={payload.get('owner')} ws={payload.get('ws')} exp={payload.get('exp')} scope={payload.get('scope')}")
        return 0 if valid else 1

    if args.cmd == "info":
        payload = decode_token(args.token)
        if payload is None:
            print("decode failed", file=sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(_cli())
