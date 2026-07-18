#!/usr/bin/env python3
"""deepseek-model-probe.py — resolve DeepSeek logical aliases to API model_ids.

R36 pathspec via tools/agent-pathspec-register.py
(lane-DEEPSEEK-INTEGRATION-CORE entry in agent_pathspec.json).

DEEPSEEK-INTEGRATION-CORE (2026-05-26). DeepSeek ships two product
tiers - "Flash" (1M context, $0.14/M cache-miss input) and "Pro" (200K
context, $0.435/M cache-miss input) - but the operator-cited names
`deepseek-v4-flash` and `deepseek-v4-pro` may not match the actual API
`model_id` the OpenAI-compat or Anthropic-compat endpoint accepts.

This tool probes a list of candidate model_ids against the live
DeepSeek Anthropic-compat endpoint and writes a canonical alias file
to `reference/deepseek_model_aliases.json`. The alias file maps the
operator-cited logical names (`deepseek-flash` / `deepseek-pro`) to
the actual API model_id that returned a 200 response.

Default candidate list (operator-cited + recent DeepSeek naming
conventions, ordered from most likely to least likely):

    deepseek-flash:
      - deepseek-v4-flash
      - deepseek-v4-flash-preview
      - deepseek-flash-latest
      - deepseek-coder-v4-flash
      - deepseek-v4
      - deepseek-chat-flash

    deepseek-pro:
      - deepseek-v4-pro
      - deepseek-v4-pro-preview
      - deepseek-pro-latest
      - deepseek-coder-v4-pro
      - deepseek-v4-coder
      - deepseek-reasoner

The probe sends a one-character `ping` to each candidate via the
Anthropic-compat /v1/messages endpoint and records the response. The
first 2xx response wins; subsequent candidates are still probed so
the alias file lists every responding model_id (useful when the
account upgrades and a wider catalog opens up).

Insufficient-balance accounts (HTTP 402) are treated as "model is
recognized but cannot be invoked" - the alias is still recorded with
a `balance_required=true` marker so the dispatcher can resolve the
alias without making a live call.

Mock-mode (`--mock`) skips the network entirely and emits a synthetic
alias file using the operator-cited defaults; used by tests and by
operators who want to inspect the schema without spending API budget.

Usage
-----
    python3 tools/deepseek-model-probe.py [--mock] [--candidates-file <path>]
                                           [--out reference/deepseek_model_aliases.json]
                                           [--timeout 10] [--json]

The tool is stdlib-only (urllib.request); no third-party deps.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import socket  # noqa: F401  - documented stdlib surface; used via urlopen
import sys
import urllib.error
import urllib.parse
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "reference" / "deepseek_model_aliases.json"
DEEPSEEK_ENDPOINT = "https://api.deepseek.com/anthropic/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

_DEFAULT_CANDIDATES: dict[str, list[str]] = {
    "deepseek-flash": [
        "deepseek-v4-flash",
        "deepseek-v4-flash-preview",
        "deepseek-flash-latest",
        "deepseek-coder-v4-flash",
        "deepseek-v4",
        "deepseek-chat-flash",
    ],
    "deepseek-pro": [
        "deepseek-v4-pro",
        "deepseek-v4-pro-preview",
        "deepseek-pro-latest",
        "deepseek-coder-v4-pro",
        "deepseek-v4-coder",
        "deepseek-reasoner",
    ],
}


def _load_candidates(path: pathlib.Path | None) -> dict[str, list[str]]:
    if path is None:
        return {k: list(v) for k, v in _DEFAULT_CANDIDATES.items()}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(
            json.dumps({"warn": f"candidates-file-unreadable: {e}"}),
            file=sys.stderr,
        )
        return {k: list(v) for k, v in _DEFAULT_CANDIDATES.items()}
    if not isinstance(data, dict):
        return {k: list(v) for k, v in _DEFAULT_CANDIDATES.items()}
    out: dict[str, list[str]] = {}
    for k, v in data.items():
        if isinstance(v, list) and all(isinstance(x, str) for x in v):
            out[k] = v
    return out or {k: list(v) for k, v in _DEFAULT_CANDIDATES.items()}


def _probe_one(model_id: str, *, api_key: str, timeout: float) -> dict:
    """Probe a single model_id; return the classification record."""
    body = json.dumps({
        "model": model_id,
        "max_tokens": 8,
        "messages": [
            {"role": "user", "content": "ping"},
        ],
    }).encode("utf-8")
    req = urllib.request.Request(
        DEEPSEEK_ENDPOINT,
        data=body,
        method="POST",
    )
    req.add_header("x-api-key", api_key)
    req.add_header("anthropic-version", ANTHROPIC_VERSION)
    req.add_header("content-type", "application/json")
    t_start = dt.datetime.now(dt.timezone.utc)
    rec: dict = {
        "model_id": model_id,
        "endpoint": DEEPSEEK_ENDPOINT,
        "timestamp": t_start.isoformat(),
    }
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.getcode()
            body_text = resp.read(1024).decode("utf-8", errors="replace")
            rec["http_status"] = status
            rec["classification"] = "responded-2xx" if 200 <= status < 300 else f"http-{status}"
            rec["body_head"] = body_text[:256]
            rec["balance_required"] = False
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            body_text = e.fp.read(1024).decode("utf-8", errors="replace") if e.fp else ""
        except Exception:
            body_text = ""
        rec["http_status"] = status
        rec["body_head"] = body_text[:256]
        # 402 = Payment Required; the model_id IS recognized but the
        # account is below the balance threshold. Treat as a positive
        # signal for alias resolution.
        if status == 402:
            rec["classification"] = "recognized-balance-required"
            rec["balance_required"] = True
        elif status == 401:
            rec["classification"] = "auth-failed"
            rec["balance_required"] = False
        elif status == 404:
            rec["classification"] = "model-not-found"
            rec["balance_required"] = False
        elif status == 400 and "model" in body_text.lower():
            rec["classification"] = "model-not-found"
            rec["balance_required"] = False
        else:
            rec["classification"] = f"http-{status}"
            rec["balance_required"] = False
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        rec["http_status"] = 0
        rec["classification"] = "transport-error"
        rec["error"] = str(e)
        rec["balance_required"] = False
    return rec


def _synthesize_mock_aliases(candidates: dict[str, list[str]]) -> dict:
    """Mock-mode synthetic alias file using the operator-cited defaults."""
    aliases = {}
    for logical, cand_list in candidates.items():
        first = cand_list[0] if cand_list else logical
        aliases[logical] = {
            "api_model_id": first,
            "resolution": "mock-mode-default",
            "balance_required": False,
            "probed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "candidates_tried": [],
        }
    return {
        "schema": "auditooor.deepseek_model_aliases.v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "endpoint": DEEPSEEK_ENDPOINT,
        "mode": "mock",
        "aliases": aliases,
    }


def probe_all(
    *,
    candidates: dict[str, list[str]],
    api_key: str | None,
    timeout: float,
    mock: bool,
) -> dict:
    """Probe each candidate per logical alias; return alias file dict."""
    if mock or not api_key:
        result = _synthesize_mock_aliases(candidates)
        if not api_key and not mock:
            result["mode"] = "no-api-key-fallback-to-mock"
        return result
    aliases: dict[str, dict] = {}
    for logical, cand_list in candidates.items():
        tried: list[dict] = []
        winner: dict | None = None
        for model_id in cand_list:
            row = _probe_one(model_id, api_key=api_key, timeout=timeout)
            tried.append(row)
            cls = row.get("classification", "")
            if cls in ("responded-2xx", "recognized-balance-required") and winner is None:
                winner = row
        if winner is None:
            # Fall back to the first candidate so the dispatcher has
            # SOMETHING to send (operator-cited default); flag the
            # absence of a verified alias so callers know.
            aliases[logical] = {
                "api_model_id": cand_list[0] if cand_list else logical,
                "resolution": "no-candidate-recognized",
                "balance_required": False,
                "probed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "candidates_tried": tried,
            }
        else:
            aliases[logical] = {
                "api_model_id": winner.get("model_id"),
                "resolution": winner.get("classification"),
                "balance_required": bool(winner.get("balance_required")),
                "probed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "candidates_tried": tried,
            }
    return {
        "schema": "auditooor.deepseek_model_aliases.v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "endpoint": DEEPSEEK_ENDPOINT,
        "mode": "live",
        "aliases": aliases,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mock",
        action="store_true",
        help=(
            "Skip the network call and emit a synthetic alias file. "
            "Required when DEEPSEEK_API_KEY is unset or the account has "
            "insufficient balance for a 1-token probe."
        ),
    )
    parser.add_argument(
        "--candidates-file",
        type=pathlib.Path,
        default=None,
        help=(
            "Optional JSON file overriding the default candidate list. "
            "Schema: { 'deepseek-flash': [<id>, ...], 'deepseek-pro': "
            "[<id>, ...] }."
        ),
    )
    parser.add_argument(
        "--out",
        type=pathlib.Path,
        default=DEFAULT_OUT,
        help=f"Output alias file (default: {DEFAULT_OUT})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-candidate HTTP timeout in seconds (default: 10).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Also write the result to stdout as a single JSON document.",
    )
    args = parser.parse_args(argv)

    api_key = os.environ.get("DEEPSEEK_API_KEY")
    candidates = _load_candidates(args.candidates_file)
    result = probe_all(
        candidates=candidates,
        api_key=api_key,
        timeout=args.timeout,
        mock=args.mock,
    )
    out = args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        # Operator-friendly summary line per alias.
        for logical, row in result.get("aliases", {}).items():
            print(
                f"{logical} -> {row.get('api_model_id')} "
                f"(resolution={row.get('resolution')}, "
                f"balance_required={row.get('balance_required')})"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
