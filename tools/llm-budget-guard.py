#!/usr/bin/env python3
"""llm-budget-guard.py — bounded-window call budget for LLM-driven loops.

Background
----------
Codex P0 #5 from the PR #224 review: forever-mode loops at
``/tmp/forever_overnight.sh`` and ``/tmp/auto_improvement_loop_v2.sh``
ran 5+5 LLM calls every ~60s. Codex paused them because token-burn
risk is real and ROI was approximately zero (no shipped findings).
The mandate was: any future loop must run on bounded events with hard
ceilings — never "spin forever and pray."

This tool is the **library half** of the fix. It exposes a small,
stdlib-only API any LLM-calling script can import to enforce
per-provider, per-window call-and-token budgets, and a CLI for ad-hoc
status / check / reset operations.

The PR that ships this file does **not** wire it into
``tools/llm-dispatch.py`` or any forever loop — that's a deliberate
follow-up per Codex's "small and separate" rule. Shipping the library
on its own keeps the diff reviewable and avoids coupling a behavioral
change to a brand-new mechanism.

Design contract
---------------
- **Stdlib only.** No new pip dependencies.
- **Append-only call log** at ``tools/calibration/llm_budget_log.jsonl``.
  Manual surgery (e.g., ``reset``) appends an audit record; the file
  is never silently rewritten.
- **Rolling window** computed at query time, not via background timer.
  ``window_status`` looks at log entries in the last ``window_minutes``
  for the requested provider and aggregates calls + tokens.
- **Two ceilings per provider**: ``max_calls`` and ``max_tokens``.
  Either being exhausted blocks ``may_call`` until the oldest in-window
  entry rolls off.
- **Graceful-exit margin** (``soft_ratio``, default 0.85): callers can
  ask whether they're "near the limit" so a long-running loop can wind
  down its current iteration and exit cleanly before being blocked.
- **Provider whitelist** is the budget-config keys. Unknown providers
  are rejected — typos in caller code should not silently bypass the
  guard.
- **Reset semantics**: appends a synthetic ``RESET`` audit record. All
  subsequent ``window_status`` queries treat the most recent RESET ts
  per provider as a *floor* — real call entries older than that floor
  are excluded from the window. The log itself is never rewritten.

Schema (config — ``tools/calibration/llm_budget.json``)::

    {
      "providers": {
        "kimi":    {"window_minutes": 60, "max_calls": 180,
                    "max_tokens": 1800000, "soft_ratio": 0.9},
        "minimax": {"window_minutes": 60, "max_calls": 240,
                    "max_tokens": 2400000, "soft_ratio": 0.9}
      }
    }

Schema (log — ``tools/calibration/llm_budget_log.jsonl``)::

    {"ts": "2026-04-25T10:00:00Z", "provider": "kimi",
     "success": true, "tokens_used": 1234, "note": null}

``note`` is used only for audit records (``RESET:<reason>``). Real
call records keep it ``null`` and count toward window usage; audit
records do NOT count.

Subcommands::

    llm-budget-guard.py status [--provider P] [--config PATH]
    llm-budget-guard.py check  <provider> [--config PATH] [--soft]
    llm-budget-guard.py reset  <provider> [--config PATH] [--reason STR]

Set ``AUDITOOOR_LLM_BUDGET_CONFIG`` to use a tuned provider profile
without disabling the guard. This is the preferred paid-tier/aggressive
mode because call accounting still lands in the append-only budget log.

Library use::

    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "llm_budget_guard", "tools/llm-budget-guard.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    guard = m.LlmBudgetGuard()
    ok, reason = guard.may_call("kimi")
    if not ok:
        sys.exit(f"budget exhausted: {reason}")
    # ... call LLM ...
    guard.record_call("kimi", tokens_used=1234)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

THIS_FILE = Path(__file__).resolve()
TOOLS_DIR = THIS_FILE.parent
CALIBRATION_DIR = TOOLS_DIR / "calibration"
DEFAULT_CONFIG_PATH = CALIBRATION_DIR / "llm_budget.json"
DEFAULT_LOG_PATH = CALIBRATION_DIR / "llm_budget_log.jsonl"
BUDGET_CONFIG_ENV_VAR = "AUDITOOOR_LLM_BUDGET_CONFIG"


REQUIRED_PROVIDER_FIELDS = ("window_minutes", "max_calls", "max_tokens")
DEFAULT_SOFT_RATIO = 0.85
RESET_NOTE_PREFIX = "RESET:"


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp into a tz-aware UTC datetime.

    Accepts both ``...Z`` and ``...+00:00`` shapes. Naive timestamps are
    interpreted as UTC, matching how the writer emits them.
    """
    if not isinstance(ts, str):
        raise ValueError(f"ts must be str, got {type(ts).__name__}")
    raw = ts.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"invalid ts {ts!r}: {exc}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

class ProviderBudget:
    """Per-provider budget knobs. Plain class (not dataclass) so the
    module imports cleanly under odd loader conditions on 3.14."""

    __slots__ = ("name", "window_minutes", "max_calls", "max_tokens",
                 "soft_ratio")

    def __init__(
        self,
        name: str,
        window_minutes: int,
        max_calls: int,
        max_tokens: int,
        soft_ratio: float = DEFAULT_SOFT_RATIO,
    ) -> None:
        self.name = name
        self.window_minutes = int(window_minutes)
        self.max_calls = int(max_calls)
        self.max_tokens = int(max_tokens)
        self.soft_ratio = float(soft_ratio)

    def window(self) -> timedelta:
        return timedelta(minutes=self.window_minutes)

    def __repr__(self) -> str:  # pragma: no cover (debug aid)
        return (
            f"ProviderBudget({self.name!r}, "
            f"window_minutes={self.window_minutes}, "
            f"max_calls={self.max_calls}, max_tokens={self.max_tokens}, "
            f"soft_ratio={self.soft_ratio})"
        )


def _validate_provider_budget(name: str, raw: Dict[str, Any]) -> ProviderBudget:
    if not isinstance(raw, dict):
        raise ValueError(f"provider {name!r}: budget must be dict")
    for field in REQUIRED_PROVIDER_FIELDS:
        if field not in raw:
            raise ValueError(
                f"provider {name!r}: missing required field {field!r}"
            )
    win = raw["window_minutes"]
    cal = raw["max_calls"]
    tok = raw["max_tokens"]
    soft = raw.get("soft_ratio", DEFAULT_SOFT_RATIO)
    if not (isinstance(win, int) and not isinstance(win, bool) and win > 0):
        raise ValueError(f"provider {name!r}: window_minutes must be int > 0")
    if not (isinstance(cal, int) and not isinstance(cal, bool) and cal > 0):
        raise ValueError(f"provider {name!r}: max_calls must be int > 0")
    if not (isinstance(tok, int) and not isinstance(tok, bool) and tok > 0):
        raise ValueError(f"provider {name!r}: max_tokens must be int > 0")
    if not (isinstance(soft, (int, float)) and not isinstance(soft, bool)
            and 0 < float(soft) <= 1.0):
        raise ValueError(
            f"provider {name!r}: soft_ratio must be in (0, 1], got {soft!r}"
        )
    return ProviderBudget(
        name=name,
        window_minutes=int(win),
        max_calls=int(cal),
        max_tokens=int(tok),
        soft_ratio=float(soft),
    )


def load_config(path: Optional[Path] = None) -> Dict[str, ProviderBudget]:
    """Load ``llm_budget.json``; return ``{provider_name: ProviderBudget}``.

    Missing file is an error — the guard exists to enforce a config, and
    silently defaulting would defeat the purpose. Use the shipped
    ``tools/calibration/llm_budget.json`` as the default sample.
    """
    env_path = os.environ.get(BUDGET_CONFIG_ENV_VAR)
    p = Path(path) if path else Path(env_path) if env_path else DEFAULT_CONFIG_PATH
    if not p.exists():
        raise FileNotFoundError(f"budget config not found: {p}")
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"budget config {p} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict) or "providers" not in raw:
        raise ValueError(f"budget config {p} missing top-level 'providers' key")
    providers_raw = raw["providers"]
    if not isinstance(providers_raw, dict) or not providers_raw:
        raise ValueError(
            f"budget config {p}: 'providers' must be non-empty dict"
        )
    out: Dict[str, ProviderBudget] = {}
    for name, body in providers_raw.items():
        out[name] = _validate_provider_budget(name, body)
    return out


# ---------------------------------------------------------------------------
# Log read/write
# ---------------------------------------------------------------------------

def _validate_log_entry(entry: Dict[str, Any]) -> None:
    for field in ("ts", "provider", "success", "tokens_used"):
        if field not in entry:
            raise ValueError(f"log entry missing required field: {field}")
    if not isinstance(entry["provider"], str) or not entry["provider"]:
        raise ValueError("log entry: provider must be non-empty str")
    if not isinstance(entry["success"], bool):
        raise ValueError("log entry: success must be bool")
    tok = entry["tokens_used"]
    if isinstance(tok, bool) or not isinstance(tok, int) or tok < 0:
        raise ValueError("log entry: tokens_used must be int >= 0")
    _parse_iso(entry["ts"])  # raises if malformed


def load_log(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    p = Path(path) if path else DEFAULT_LOG_PATH
    if not p.exists():
        return []
    out: List[Dict[str, Any]] = []
    for ln, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{p}:{ln}: invalid JSON: {exc}") from exc
        _validate_log_entry(entry)
        out.append(entry)
    return out


def append_log(entry: Dict[str, Any], path: Optional[Path] = None) -> None:
    _validate_log_entry(entry)
    p = Path(path) if path else DEFAULT_LOG_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, sort_keys=True, separators=(",", ": "))
    with p.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


# ---------------------------------------------------------------------------
# Window math
# ---------------------------------------------------------------------------

def _is_audit_record(entry: Dict[str, Any]) -> bool:
    note = entry.get("note") or ""
    return bool(note)


def _latest_reset_per_provider(
    entries: Iterable[Dict[str, Any]],
) -> Dict[str, datetime]:
    """Latest RESET ts per provider, used as the in-window floor."""
    out: Dict[str, datetime] = {}
    for e in entries:
        note = e.get("note") or ""
        if not note.startswith(RESET_NOTE_PREFIX):
            continue
        ts = _parse_iso(e["ts"])
        prev = out.get(e["provider"])
        if prev is None or ts > prev:
            out[e["provider"]] = ts
    return out


def _entries_in_window(
    entries: Iterable[Dict[str, Any]],
    provider: str,
    window: timedelta,
    now: datetime,
    reset_floor: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """Return real call entries (not audit records) for ``provider`` whose
    timestamp lies within ``[now - window, now]`` AND on or after any
    applicable reset floor.

    Audit records (``note`` set) do NOT count toward window usage. They
    exist purely for the human-readable audit trail of resets and
    manual interventions.
    """
    cutoff = now - window
    out: List[Dict[str, Any]] = []
    for e in entries:
        if e.get("provider") != provider:
            continue
        if _is_audit_record(e):
            continue
        ts = _parse_iso(e["ts"])
        if not (cutoff <= ts <= now):
            continue
        if reset_floor is not None and ts < reset_floor:
            continue
        out.append(e)
    return out


# ---------------------------------------------------------------------------
# The Guard
# ---------------------------------------------------------------------------

class LlmBudgetGuard:
    """Per-provider call-and-token budget guard.

    Construct once per script. ``may_call`` and ``record_call`` re-read
    the on-disk log every call so multiple processes can share the same
    budget cleanly (small writes, append-only — race window is bounded
    by the size of one append).
    """

    def __init__(
        self,
        config_path: Optional[Path] = None,
        log_path: Optional[Path] = None,
        now_fn: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self._config_path = (
            Path(config_path)
            if config_path
            else Path(os.environ[BUDGET_CONFIG_ENV_VAR])
            if os.environ.get(BUDGET_CONFIG_ENV_VAR)
            else DEFAULT_CONFIG_PATH
        )
        self._log_path = Path(log_path) if log_path else DEFAULT_LOG_PATH
        self._now_fn: Callable[[], datetime] = now_fn or _utcnow
        self._budgets: Dict[str, ProviderBudget] = load_config(
            self._config_path
        )

    # -- introspection ------------------------------------------------------

    @property
    def providers(self) -> List[str]:
        return sorted(self._budgets)

    def budget_for(self, provider: str) -> ProviderBudget:
        if provider not in self._budgets:
            raise KeyError(
                f"unknown provider {provider!r}; configured: "
                f"{sorted(self._budgets)}"
            )
        return self._budgets[provider]

    # -- the three documented API methods -----------------------------------

    def window_status(self, provider: str) -> Dict[str, Any]:
        """Current window usage for ``provider``.

        Returns a plain dict::

            {
              "provider": "kimi",
              "window_minutes": 60,
              "calls_used": 7,
              "calls_max": 30,
              "tokens_used": 14523,
              "tokens_max": 60000,
              "calls_remaining": 23,
              "tokens_remaining": 45477,
              "near_soft_limit": false,
              "exhausted": false,
              "exhausted_reason": null,
              "oldest_in_window_ts": "2026-04-25T09:14:21Z" | null
            }
        """
        budget = self.budget_for(provider)
        now = self._now_fn()
        log = load_log(self._log_path)
        floors = _latest_reset_per_provider(log)
        floor = floors.get(provider)
        in_win = _entries_in_window(
            log, provider, budget.window(), now, reset_floor=floor
        )

        calls_used = len(in_win)
        tokens_used = sum(int(e.get("tokens_used") or 0) for e in in_win)

        calls_remaining = budget.max_calls - calls_used
        tokens_remaining = budget.max_tokens - tokens_used

        exhausted = False
        reason: Optional[str] = None
        if calls_used >= budget.max_calls:
            exhausted = True
            reason = (
                f"calls budget exhausted: "
                f"{calls_used}/{budget.max_calls} in last "
                f"{budget.window_minutes}min"
            )
        elif tokens_used >= budget.max_tokens:
            exhausted = True
            reason = (
                f"tokens budget exhausted: "
                f"{tokens_used}/{budget.max_tokens} in last "
                f"{budget.window_minutes}min"
            )

        # "Near soft limit" — graceful-exit signal. Loops should check
        # this at the top of each iteration and break cleanly when true,
        # rather than waiting for hard exhaustion mid-batch.
        soft_calls = budget.max_calls * budget.soft_ratio
        soft_tokens = budget.max_tokens * budget.soft_ratio
        near_soft = (calls_used >= soft_calls) or (tokens_used >= soft_tokens)

        oldest_ts: Optional[str] = None
        if in_win:
            oldest = min(in_win, key=lambda e: _parse_iso(e["ts"]))
            oldest_ts = oldest["ts"]

        return {
            "provider": provider,
            "window_minutes": budget.window_minutes,
            "calls_used": calls_used,
            "calls_max": budget.max_calls,
            "tokens_used": tokens_used,
            "tokens_max": budget.max_tokens,
            "calls_remaining": max(0, calls_remaining),
            "tokens_remaining": max(0, tokens_remaining),
            "near_soft_limit": bool(near_soft),
            "exhausted": exhausted,
            "exhausted_reason": reason,
            "oldest_in_window_ts": oldest_ts,
        }

    def may_call(
        self, provider: str, *, soft: bool = False
    ) -> Tuple[bool, Optional[str]]:
        """Return ``(allowed, reason)`` for the next call.

        - ``allowed=True, reason=None`` — under the hard ceiling.
        - ``allowed=False, reason=...`` — at or over the hard ceiling.
        - With ``soft=True``: also returns False (with a near-limit
          reason) if the soft threshold is crossed, so callers can opt
          in to early graceful exit.
        """
        st = self.window_status(provider)
        if st["exhausted"]:
            return False, st["exhausted_reason"]
        if soft and st["near_soft_limit"]:
            budget = self.budget_for(provider)
            return False, (
                f"near soft limit: "
                f"calls {st['calls_used']}/{st['calls_max']}, "
                f"tokens {st['tokens_used']}/{st['tokens_max']} "
                f"(soft_ratio={budget.soft_ratio})"
            )
        return True, None

    def record_call(
        self,
        provider: str,
        tokens_used: int,
        *,
        success: bool = True,
        ts: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Append a call record to the log. Returns the entry written."""
        # Reject typos at the boundary — if the caller has a provider
        # not in the budget config, that's a bug, not a "log everything"
        # case.
        if provider not in self._budgets:
            raise KeyError(
                f"unknown provider {provider!r}; configured: "
                f"{sorted(self._budgets)}"
            )
        if (isinstance(tokens_used, bool)
                or not isinstance(tokens_used, int)
                or tokens_used < 0):
            raise ValueError(
                f"tokens_used must be int >= 0, got {tokens_used!r}"
            )
        entry = {
            "ts": ts or _iso(self._now_fn()),
            "provider": provider,
            "success": bool(success),
            "tokens_used": int(tokens_used),
            "note": None,
        }
        append_log(entry, self._log_path)
        return entry

    # -- audit / emergency --------------------------------------------------

    def reset(
        self, provider: str, *, reason: str = "manual reset"
    ) -> Dict[str, Any]:
        """Emergency window reset.

        Appends a synthetic ``RESET:<reason>`` audit record (the prior
        log is never rewritten). All subsequent ``window_status``
        queries treat the most recent RESET ts per provider as a floor:
        real call entries strictly older than that floor are excluded
        from the window. Audit records themselves never count toward
        window usage.
        """
        if provider not in self._budgets:
            raise KeyError(
                f"unknown provider {provider!r}; configured: "
                f"{sorted(self._budgets)}"
            )
        entry = {
            "ts": _iso(self._now_fn()),
            "provider": provider,
            "success": True,
            "tokens_used": 0,
            "note": f"{RESET_NOTE_PREFIX}{reason}",
        }
        append_log(entry, self._log_path)
        return entry


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_status(status: Dict[str, Any]) -> None:
    soft_marker = " [SOFT-LIMIT]" if status["near_soft_limit"] else ""
    hard_marker = " [EXHAUSTED]" if status["exhausted"] else ""
    print(
        f"{status['provider']}: "
        f"{status['calls_used']}/{status['calls_max']} calls, "
        f"{status['tokens_used']}/{status['tokens_max']} tokens "
        f"in {status['window_minutes']}min window"
        f"{soft_marker}{hard_marker}"
    )
    if status["exhausted"]:
        print(f"  reason: {status['exhausted_reason']}")
    if status["oldest_in_window_ts"]:
        print(f"  oldest in-window call: {status['oldest_in_window_ts']}")


def cmd_status(args: argparse.Namespace) -> int:
    guard = LlmBudgetGuard(config_path=args.config)
    providers = [args.provider] if args.provider else guard.providers
    for p in providers:
        try:
            st = guard.window_status(p)
        except KeyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        _print_status(st)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    guard = LlmBudgetGuard(config_path=args.config)
    try:
        ok, reason = guard.may_call(args.provider, soft=args.soft)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if ok:
        print(f"OK: {args.provider} may proceed")
        return 0
    print(f"BLOCKED: {args.provider}: {reason}", file=sys.stderr)
    return 1


def cmd_reset(args: argparse.Namespace) -> int:
    guard = LlmBudgetGuard(config_path=args.config)
    try:
        entry = guard.reset(args.provider, reason=args.reason)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        f"RESET: {args.provider} at {entry['ts']} "
        f"(reason={args.reason!r}); audit record appended."
    )
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="llm-budget-guard.py",
        description=(
            "Bounded-window call budget for LLM-driven loops. Library + "
            "CLI; this PR ships the library only — wiring into "
            "llm-dispatch and forever loops is a follow-up."
        ),
    )
    p.add_argument(
        "--config",
        type=Path,
        default=None,
        help=f"Budget config path (default: {DEFAULT_CONFIG_PATH}).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_status = sub.add_parser("status", help="Print current window usage.")
    p_status.add_argument(
        "--provider",
        default=None,
        help="Limit output to one provider (default: all configured).",
    )
    p_status.set_defaults(func=cmd_status)

    p_check = sub.add_parser(
        "check",
        help="Exit 0 if may-call, 1 if blocked, 2 on config/error.",
    )
    p_check.add_argument("provider")
    p_check.add_argument(
        "--soft",
        action="store_true",
        help="Also block when at the soft-limit ratio (graceful-exit signal).",
    )
    p_check.set_defaults(func=cmd_check)

    p_reset = sub.add_parser(
        "reset",
        help="Emergency window reset (appends an audit record).",
    )
    p_reset.add_argument("provider")
    p_reset.add_argument(
        "--reason",
        default="manual reset",
        help="Reason logged in the audit record.",
    )
    p_reset.set_defaults(func=cmd_reset)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
