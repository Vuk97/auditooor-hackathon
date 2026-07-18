#!/usr/bin/env python3
"""llm-preflight-auth.py — cheap provider-config / auth readiness check.

V5-P0-04 (Gap 44): provider-config drift goes undetected today. By the
time a long source-mining campaign starts, a stale ``KIMI_API_KEY``
or expired OAuth token only surfaces after the first real dispatch. This
tool resolves auth for each known provider WITHOUT logging secrets and
optionally performs a tiny smoke dispatch so operators can verify
readiness in seconds.

Two modes:

- ``--dry-run`` (default usable for offline replay): does NOT contact any
  provider. Reports which auth-resolution path would resolve per
  provider, exits 0 even when a provider has no key configured (the
  no-key state is reported in the per-provider record). Exit 1 only when
  ``--provider <name>`` is requested explicitly AND that provider has
  no resolvable auth path.

- live (no ``--dry-run``): actually POSTs a small ``OK``-prompt to each
  provider's Anthropic-compatible Messages API with ``max_tokens=200``.
  Requires the same network-consent env var as ``tools/llm-dispatch.py``
  (``AUDITOOOR_LLM_NETWORK_CONSENT=1`` or ``ADVERSARIAL_LIVE_CONSENT=1``).
  Exit 0 if all attempted providers usable, 1 if any provider explicitly
  fails its smoke dispatch.

Output goes to stdout. Use ``--json`` for a machine-readable single-line
JSON record (one line per provider in ``--provider all`` mode, otherwise
one line for the single provider). The default plain-text format is
human-friendly.

Audit trail
-----------
Every invocation writes ``agent_outputs/llm_preflight_<ts>.json``
containing per-provider ``{usable, resolution_path, error_class}``
entries. Auth tokens, OAuth file contents, and provider responses are
NEVER persisted. ``error_class`` is a short symbolic label (e.g.
``no-key``, ``http-401``, ``transport``, ``malformed-response``) — the
underlying exception message is intentionally NOT stored because it can
echo headers or body fragments containing the key on some providers.

Hard rules (mirror llm-dispatch.py)
-----------------------------------
- Stdlib only.
- No writes to ``submissions/``.
- Never echo secrets, OAuth file contents, response bodies, or request
  bodies in stdout / stderr / audit trail.
"""
from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Config — kept local so this tool is independent of llm-dispatch importability
# ---------------------------------------------------------------------------

KNOWN_PROVIDERS: Tuple[str, ...] = ("kimi", "minimax", "anthropic")

# Mirror of llm-dispatch defaults; we intentionally re-state them here so
# this script is self-contained and does not rely on importing the
# hyphen-named dispatch module on every preflight call.
_DEFAULT_BASE_URLS: Dict[str, str] = {
    "kimi": "https://api.kimi.com/coding",
    "minimax": "https://api.minimax.io/anthropic",
    "anthropic": "https://api.anthropic.com",
}
_DEFAULT_MODELS: Dict[str, str] = {
    "kimi": "kimi-for-coding",
    "minimax": "MiniMax-M2.7",
    "anthropic": "claude-opus-4-5",
}

ANTHROPIC_VERSION = "2023-06-01"
MESSAGES_PATH = "/v1/messages"

# Smoke-dispatch knobs — small enough to be cheap, large enough that a
# real provider has room to reply with "OK".
SMOKE_PROMPT = "Respond with just 'OK'. This is a connectivity smoke test."
SMOKE_MAX_TOKENS = 200
SMOKE_TIMEOUT_S = 30.0


# Resolution-path symbolic labels. These are the only strings ever
# written to the audit trail or stdout for the resolution path. We
# deliberately do NOT include the env-var value or the OAuth file
# contents — only the *which path won* fact.
PATH_ENV_PROVIDER_KEY = "env-provider-key"          # e.g. KIMI_API_KEY env
PATH_KIMI_OAUTH_FILE = "kimi-oauth-file"            # ~/.kimi/.../kimi-code.json
PATH_SETTINGS_PROVIDER_KEY = "settings-provider-key"
PATH_SETTINGS_ANTHROPIC_TOKEN = "settings-anthropic-token"
PATH_ENV_ANTHROPIC_KEY = "env-anthropic-key"
PATH_ENV_ANTHROPIC_TOKEN = "env-anthropic-token"
PATH_NONE = "none"


# Symbolic error classes. These are the only error labels ever written
# to stdout or the audit trail. Underlying exception messages are
# discarded to avoid leaking auth-tied error bodies.
ERR_NO_KEY = "no-key"
ERR_NO_CONSENT = "no-consent"
ERR_HTTP_401 = "http-401"
ERR_HTTP_403 = "http-403"
ERR_HTTP_429 = "http-429"
ERR_HTTP_4XX = "http-4xx"
ERR_HTTP_5XX = "http-5xx"
ERR_TRANSPORT = "transport"
ERR_MALFORMED_RESPONSE = "malformed-response"
ERR_TIMEOUT = "timeout"


EXIT_OK = 0
EXIT_FAIL = 1
EXIT_CANNOT_RUN = 2


# ---------------------------------------------------------------------------
# Auth resolution (read-only, never echoes secrets)
# ---------------------------------------------------------------------------

_KIMI_OAUTH_FILE_DEFAULT = (
    pathlib.Path.home() / ".kimi" / "credentials" / "kimi-code.json"
)


def _settings_json_env() -> Dict[str, Any]:
    """Read ``~/.claude/settings.json`` ``env`` map; never raises."""
    path = pathlib.Path.home() / ".claude" / "settings.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    env = data.get("env")
    if not isinstance(env, dict):
        return {}
    return env


def _kimi_oauth_token_from_file() -> Tuple[Optional[str], Optional[str]]:
    """Return ``(token, path_label)`` for the kimi OAuth file fallback.

    Path label is the pathlib path string (NOT secret). Returns
    ``(None, None)`` when the file is missing or malformed. We never
    surface the file's contents or the parser exception in the returned
    tuple — even in error mode the caller only learns "missing /
    malformed", never the bytes that triggered it.
    """
    override = os.environ.get("AUDITOOOR_KIMI_OAUTH_FILE")
    path = pathlib.Path(override) if override else _KIMI_OAUTH_FILE_DEFAULT
    if not path.is_file():
        return None, None
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, ValueError):
        return None, None
    if not isinstance(data, dict):
        return None, None
    token = data.get("access_token")
    if not isinstance(token, str) or not token:
        return None, None
    return token, str(path)


def resolve_auth(
    provider: str,
) -> Tuple[Optional[str], str, Optional[str]]:
    """Resolve auth for ``provider`` without echoing the secret.

    Returns ``(api_key, resolution_path, oauth_file_path_or_None)``.

    - ``api_key``: the resolved key, or ``None`` if no path resolved.
      Callers must never log this value.
    - ``resolution_path``: one of the ``PATH_*`` symbolic labels above
      (always safe to log).
    - ``oauth_file_path_or_None``: only set for the kimi OAuth-file
      fallback, otherwise ``None``. The path string is safe to log.
    """
    if provider == "kimi":
        env_key = os.environ.get("KIMI_API_KEY")
        if env_key:
            return env_key, PATH_ENV_PROVIDER_KEY, None
        oauth_token, oauth_path = _kimi_oauth_token_from_file()
        if oauth_token:
            return oauth_token, PATH_KIMI_OAUTH_FILE, oauth_path
        sj = _settings_json_env()
        sj_provider = sj.get("KIMI_API_KEY")
        if isinstance(sj_provider, str) and sj_provider:
            return sj_provider, PATH_SETTINGS_PROVIDER_KEY, None
        sj_anth = sj.get("ANTHROPIC_AUTH_TOKEN")
        if isinstance(sj_anth, str) and sj_anth:
            return sj_anth, PATH_SETTINGS_ANTHROPIC_TOKEN, None
        return None, PATH_NONE, None
    if provider == "minimax":
        env_key = os.environ.get("MINIMAX_API_KEY")
        if env_key:
            return env_key, PATH_ENV_PROVIDER_KEY, None
        sj = _settings_json_env()
        sj_provider = sj.get("MINIMAX_API_KEY")
        if isinstance(sj_provider, str) and sj_provider:
            return sj_provider, PATH_SETTINGS_PROVIDER_KEY, None
        sj_anth = sj.get("ANTHROPIC_AUTH_TOKEN")
        if isinstance(sj_anth, str) and sj_anth:
            return sj_anth, PATH_SETTINGS_ANTHROPIC_TOKEN, None
        return None, PATH_NONE, None
    if provider == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if api_key:
            return api_key, PATH_ENV_ANTHROPIC_KEY, None
        token = os.environ.get("ANTHROPIC_AUTH_TOKEN")
        if token:
            return token, PATH_ENV_ANTHROPIC_TOKEN, None
        return None, PATH_NONE, None
    return None, PATH_NONE, None


def _provider_endpoint(provider: str) -> Tuple[str, str]:
    """Return ``(api_url, model)`` honoring the standard env overrides."""
    if provider == "kimi":
        base = (
            os.environ.get("KIMI_ANTHROPIC_BASE_URL")
            or _DEFAULT_BASE_URLS["kimi"]
        )
        model = os.environ.get("KIMI_MODEL") or _DEFAULT_MODELS["kimi"]
    elif provider == "minimax":
        base = (
            os.environ.get("MINIMAX_ANTHROPIC_BASE_URL")
            or _DEFAULT_BASE_URLS["minimax"]
        )
        model = (
            os.environ.get("MINIMAX_MODEL") or _DEFAULT_MODELS["minimax"]
        )
    elif provider == "anthropic":
        base = (
            os.environ.get("ANTHROPIC_BASE_URL")
            or _DEFAULT_BASE_URLS["anthropic"]
        )
        model = (
            os.environ.get("ANTHROPIC_MODEL") or _DEFAULT_MODELS["anthropic"]
        )
    else:
        base = ""
        model = ""
    base = base.rstrip("/")
    if base.endswith("/v1"):
        api_url = base + "/messages"
    else:
        api_url = base + MESSAGES_PATH
    return api_url, model


def _consent_granted() -> bool:
    return (
        os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") == "1"
        or os.environ.get("ADVERSARIAL_LIVE_CONSENT") == "1"
    )


# ---------------------------------------------------------------------------
# Live smoke dispatch (only when --dry-run is NOT set)
# ---------------------------------------------------------------------------

def _classify_http_error(status: int) -> str:
    if status == 401:
        return ERR_HTTP_401
    if status == 403:
        return ERR_HTTP_403
    if status == 429:
        return ERR_HTTP_429
    if 400 <= status < 500:
        return ERR_HTTP_4XX
    if 500 <= status < 600:
        return ERR_HTTP_5XX
    return ERR_HTTP_4XX  # default conservative bucket


def _smoke_dispatch(
    provider: str,
    api_key: str,
    *,
    timeout: float = SMOKE_TIMEOUT_S,
    urlopen: Optional[Callable[..., Any]] = None,
) -> Tuple[bool, Optional[str]]:
    """POST a tiny ``OK`` prompt to the provider. Returns ``(usable, error_class)``.

    Only the symbolic ``error_class`` is returned — never the response
    body, never the exception's repr. Best-effort parse of the success
    body just confirms a non-empty ``content`` array exists.

    The ``urlopen`` parameter defaults to ``None`` and is resolved at
    call time to ``urllib.request.urlopen``. This lets tests patch
    ``urllib.request.urlopen`` after import without having to also
    re-bind the default arg (which would have been captured at function
    definition).
    """
    if urlopen is None:
        urlopen = urllib.request.urlopen
    api_url, model = _provider_endpoint(provider)
    auth_header_choice = (
        os.environ.get("AUDITOOOR_LLM_AUTH_HEADER") or "x-api-key"
    ).strip().lower()
    if auth_header_choice == "bearer":
        headers = {
            "authorization": f"Bearer {api_key}",
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
    else:
        headers = {
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
    body = {
        "model": model,
        "max_tokens": SMOKE_MAX_TOKENS,
        "messages": [{"role": "user", "content": SMOKE_PROMPT}],
    }
    body_bytes = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        api_url, data=body_bytes, method="POST", headers=headers
    )
    try:
        resp = urlopen(req, timeout=timeout)
        status = getattr(resp, "status", None) or resp.getcode()
        data = resp.read()
        try:
            resp.close()
        except Exception:
            pass
    except urllib.error.HTTPError as e:
        # HTTPError is an HTTP response; surface only the bucket label.
        # We deliberately do not read e.read() into any returned value.
        return False, _classify_http_error(e.code)
    except urllib.error.URLError:
        return False, ERR_TRANSPORT
    except (TimeoutError, OSError):
        return False, ERR_TIMEOUT
    if status < 200 or status >= 300:
        return False, _classify_http_error(int(status))
    try:
        doc = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return False, ERR_MALFORMED_RESPONSE
    content = doc.get("content")
    if not isinstance(content, list) or not content:
        return False, ERR_MALFORMED_RESPONSE
    return True, None


# ---------------------------------------------------------------------------
# Per-provider preflight record
# ---------------------------------------------------------------------------

def _check_one_provider(
    provider: str,
    *,
    dry_run: bool,
    smoke_dispatch: Callable[..., Tuple[bool, Optional[str]]] = _smoke_dispatch,
) -> Dict[str, Any]:
    """Build a per-provider record (no secrets in the returned dict)."""
    api_key, resolution_path, oauth_file = resolve_auth(provider)
    record: Dict[str, Any] = {
        "provider": provider,
        "resolution_path": resolution_path,
        "oauth_file": oauth_file,  # path string only; never the file contents
        "dry_run": dry_run,
    }
    if api_key is None:
        record["usable"] = False
        record["error_class"] = ERR_NO_KEY
        return record
    if dry_run:
        # Auth resolved; we deliberately do not contact the network.
        record["usable"] = True
        record["error_class"] = None
        return record
    if not _consent_granted():
        record["usable"] = False
        record["error_class"] = ERR_NO_CONSENT
        return record
    usable, err = smoke_dispatch(provider, api_key)
    record["usable"] = usable
    record["error_class"] = err
    return record


# ---------------------------------------------------------------------------
# Output / audit trail
# ---------------------------------------------------------------------------

def _format_text_record(record: Dict[str, Any]) -> str:
    usable = "USABLE" if record.get("usable") else "FAIL"
    err = record.get("error_class")
    err_part = f" error={err}" if err else ""
    oauth = record.get("oauth_file")
    oauth_part = f" oauth_file={oauth}" if oauth else ""
    mode = "dry-run" if record.get("dry_run") else "live"
    return (
        f"{record['provider']:9s} {usable:6s} "
        f"path={record['resolution_path']} mode={mode}{err_part}{oauth_part}"
    )


def _format_json_record(record: Dict[str, Any]) -> str:
    # Single-line JSON; no API keys, no response bodies, no exceptions.
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def _write_audit_trail(
    audit_dir: pathlib.Path, records: List[Dict[str, Any]]
) -> pathlib.Path:
    audit_dir.mkdir(parents=True, exist_ok=True)
    ts = (
        datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y%m%dT%H%M%SZ")
    )
    path = audit_dir / f"llm_preflight_{ts}.json"
    payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "records": records,
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _decide_exit_code(
    records: List[Dict[str, Any]],
    *,
    explicit_provider: Optional[str],
) -> int:
    """V5-P0-04 spec:

    - 0 if all attempted providers usable OR ``--dry-run``.
    - 1 if any provider explicitly fails.

    Special case for ``--dry-run`` + explicit single provider: when an
    explicit ``--provider X`` is requested AND its only failure mode
    would be ``no-key`` in dry-run, we still exit 1 — the operator
    asked specifically about X, and the answer is "no auth path
    resolves." Otherwise dry-run always exits 0.
    """
    failed = [r for r in records if not r.get("usable")]
    if not failed:
        return EXIT_OK
    # Explicit single-provider mode: caller wants a hard answer for X.
    if explicit_provider is not None and explicit_provider != "all":
        return EXIT_FAIL
    # Multi-provider dry-run: report no-key as a soft state, exit 0.
    if all(r.get("dry_run") for r in records):
        return EXIT_OK
    return EXIT_FAIL


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="llm-preflight-auth.py",
        description=(
            "V5-P0-04 cheap provider-auth readiness check. Resolves auth "
            "paths without logging secrets and (when --dry-run is absent) "
            "smoke-dispatches a tiny prompt to verify the credential "
            "actually works. Audit trail in agent_outputs/."
        ),
    )
    parser.add_argument(
        "--provider",
        default="all",
        choices=("kimi", "minimax", "anthropic", "all"),
        help="Provider to check (default: all known providers).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Do not contact any provider. Only report which auth path "
            "resolves. Useful for offline validation."
        ),
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit one JSON record per line instead of human-friendly text.",
    )
    parser.add_argument(
        "--audit-dir",
        default=None,
        help="Override audit-trail directory (default: ./agent_outputs).",
    )
    args = parser.parse_args(argv)

    if args.provider == "all":
        targets = list(KNOWN_PROVIDERS)
        explicit_provider: Optional[str] = None
    else:
        targets = [args.provider]
        explicit_provider = args.provider

    records: List[Dict[str, Any]] = []
    for prov in targets:
        records.append(_check_one_provider(prov, dry_run=args.dry_run))

    # Stdout — text or JSON, one line per provider.
    for rec in records:
        if args.as_json:
            sys.stdout.write(_format_json_record(rec) + "\n")
        else:
            sys.stdout.write(_format_text_record(rec) + "\n")
    sys.stdout.flush()

    # Audit trail — best-effort.
    audit_dir = (
        pathlib.Path(args.audit_dir).resolve()
        if args.audit_dir
        else pathlib.Path("agent_outputs").resolve()
    )
    try:
        _write_audit_trail(audit_dir, records)
    except Exception as e:
        sys.stderr.write(
            json.dumps({"warn": f"audit-write-failed: {e.__class__.__name__}"})
            + "\n"
        )
        sys.stderr.flush()

    return _decide_exit_code(records, explicit_provider=explicit_provider)


if __name__ == "__main__":
    sys.exit(main())
