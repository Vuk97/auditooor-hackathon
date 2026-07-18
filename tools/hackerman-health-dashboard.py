#!/usr/bin/env python3
"""Hackerman health dashboard (Wave-1, PR #726).

A single compact dashboard that aggregates the four Wave-1 health-axis
gates into one human-readable status surface:

1. ``corpus``    -- ``make hackerman-corpus-stats`` (JSON mode)
2. ``gates``     -- ``make hackerman-gates-status`` (JSON mode)
3. ``integrity`` -- ``make hackerman-integrity-check`` (JSON mode)
4. ``mcp-smoke`` -- ``make hackerman-mcp-smoke-test`` (JSON mode, ``--timeout 10``)

Each upstream tool already emits a versioned JSON envelope; this aggregator
re-uses those envelopes (it does NOT re-derive the underlying corpus stats,
gate verdicts, integrity stages, or MCP-callable smoke results). One axis
failure does not short-circuit the rest -- every axis runs and is reported.

Output
------

Default (human) output is intentionally compact (target <=80 lines, hard cap
enforced at render time). Each axis renders as a single coloured status line
plus a short detail block (<=4 lines). Colours are emitted only when stdout
is a TTY; ``--no-color`` forces them off, ``--force-color`` forces them on.

``--json`` emits the full ``auditooor.hackerman_health_dashboard.v1`` envelope
on stdout for downstream tooling. The envelope includes every axis verdict,
the upstream envelope's summary line, the elapsed wall-clock per axis, and
an ``overall_verdict`` rollup.

CLI
---

``--axis <name>``           may be repeated to restrict execution to specific
                            axes (``corpus`` / ``gates`` / ``integrity`` /
                            ``mcp-smoke``).
``--mcp-smoke-timeout <s>``  per-callable timeout passed through to the MCP
                            smoke test runner (default 10s).
``--strict``                exits non-zero when ``overall_verdict`` != pass.
``--json``                  emit machine-readable JSON envelope.
``--no-color`` / ``--force-color`` toggle ANSI colour output.
``--max-lines <n>``         hard cap on rendered human-output lines
                            (default 80).

Determinism
-----------

* Axes always run in the order declared in ``HACKERMAN_DASHBOARD_AXES``.
* The envelope's ``generated_at`` may be pinned via
  ``--generated-at`` or env ``AUDITOOOR_HEALTH_DASHBOARD_GENERATED_AT``
  for reproducible-test fixtures.
* The aggregator is read-only against the corpus tree; the only side
  effect is one subprocess per axis.

Wired into the Makefile as ``make hackerman-health-dashboard`` and
``make hackerman-health-dashboard-json``.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable


SCHEMA = "auditooor.hackerman_health_dashboard.v1"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MAX_LINES = 80
DEFAULT_MCP_SMOKE_TIMEOUT_SECONDS = 10

# ANSI colour codes (kept tiny; only used when --force-color or TTY).
_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "green": "\033[32m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "grey": "\033[90m",
}

# Normalised verdict vocabulary. Each axis's parser returns one of these.
VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"
VERDICT_MISSING = "missing"
VERDICT_ERROR = "error"
_VERDICT_COLOUR = {
    VERDICT_PASS: "green",
    VERDICT_FAIL: "red",
    VERDICT_MISSING: "yellow",
    VERDICT_ERROR: "yellow",
}


@dataclasses.dataclass
class AxisSpec:
    """Declarative spec for one dashboard axis."""

    name: str
    description: str
    # argv builder receives the dashboard context (kwargs) and returns the
    # full argv list. Kept as a callable so tests can swap stub commands.
    argv_builder: Callable[[dict[str, Any]], list[str]]
    # Parses the upstream envelope (dict) into:
    #   (verdict, summary_line, detail_lines)
    # detail_lines is a list of short strings (each rendered on its own
    # line in the human output).
    result_parser: Callable[[dict[str, Any]], tuple[str, str, list[str]]]
    # Subprocess timeout for the axis (seconds). Required so a runaway
    # upstream tool can't lock the dashboard forever.
    timeout_seconds: int = 120


@dataclasses.dataclass
class AxisResult:
    """Outcome of running one axis."""

    name: str
    verdict: str
    summary: str
    detail: list[str]
    rc: int
    elapsed_seconds: float
    envelope: dict[str, Any] | None = None
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "verdict": self.verdict,
            "summary": self.summary,
            "detail": list(self.detail),
            "rc": self.rc,
            "elapsed_seconds": self.elapsed_seconds,
            "error": self.error,
            # Envelope intentionally omitted from JSON dashboard output
            # to keep payload size bounded; callers who need the
            # full upstream envelope can call the underlying tool
            # directly.
        }


# ---------------------------------------------------------------------------
# Per-axis result parsers. Each takes the upstream tool's JSON envelope
# and returns (verdict, summary, detail_lines).
# ---------------------------------------------------------------------------


def _parse_corpus_stats(envelope: dict[str, Any]) -> tuple[str, str, list[str]]:
    """Parse ``hackerman-corpus-stats --json`` envelope."""
    stats = envelope.get("stats") or {}
    accept = envelope.get("acceptance_gate") or {}
    tier_gate = envelope.get("verification_tier_gate") or {}
    accept_v = accept.get("verdict", "")
    tier_v = tier_gate.get("verdict", "")
    accept_summary = accept.get("summary", "")
    # Acceptance gate emits "<no-verdict>" when --all is used; treat any
    # rc==0 + "fail=0" substring as pass for the dashboard rollup.
    accept_ok = (
        accept_v == VERDICT_PASS
        or (accept.get("rc") == 0 and " fail=0" in (accept_summary or ""))
    )
    tier_ok = tier_v == VERDICT_PASS or tier_gate.get("rc") == 0
    if accept_ok and tier_ok:
        verdict = VERDICT_PASS
    else:
        verdict = VERDICT_FAIL
    total = stats.get("total_records") or stats.get("hackerman_v1_total") or 0
    quarantine = (stats.get("quarantine") or {}).get("total", 0)
    subtree_count = len(stats.get("subtrees") or {})
    summary = (
        f"records={total} subtrees={subtree_count} quarantine={quarantine}"
    )
    detail = [
        f"acceptance: {accept_summary or accept_v or 'unknown'}",
        f"tier_gate: {tier_gate.get('summary', tier_v or 'unknown')}",
    ]
    return verdict, summary, detail


def _parse_gates_status(envelope: dict[str, Any]) -> tuple[str, str, list[str]]:
    """Parse ``hackerman-gates-status --json`` envelope."""
    overall = envelope.get("overall_verdict") or ""
    gate_count = envelope.get("gate_count") or 0
    verdict_counts = envelope.get("verdict_counts") or {}
    if overall == VERDICT_PASS:
        verdict = VERDICT_PASS
    elif overall in (VERDICT_FAIL, VERDICT_MISSING, VERDICT_ERROR):
        verdict = overall
    else:
        verdict = VERDICT_FAIL
    summary = (
        f"gates={gate_count} pass={verdict_counts.get('pass', 0)} "
        f"fail={verdict_counts.get('fail', 0)} "
        f"missing={verdict_counts.get('missing', 0)} "
        f"error={verdict_counts.get('error', 0)}"
    )
    detail = []
    for gate in (envelope.get("gates") or [])[:4]:
        detail.append(
            f"{gate.get('name', '?')}: {gate.get('summary', gate.get('rc', '?'))}"[:120]
        )
    return verdict, summary, detail


def _parse_integrity_check(envelope: dict[str, Any]) -> tuple[str, str, list[str]]:
    """Parse ``hackerman-integrity-check --json`` envelope."""
    overall = envelope.get("overall_verdict") or ""
    stage_count = envelope.get("stage_count") or len(envelope.get("stages") or [])
    verdict_counts = envelope.get("verdict_counts") or {}
    if overall == VERDICT_PASS:
        verdict = VERDICT_PASS
    elif overall in (VERDICT_FAIL, VERDICT_MISSING, VERDICT_ERROR):
        verdict = overall
    else:
        verdict = VERDICT_FAIL
    summary = (
        f"stages={stage_count} pass={verdict_counts.get('pass', 0)} "
        f"fail={verdict_counts.get('fail', 0)} "
        f"missing={verdict_counts.get('missing', 0)} "
        f"error={verdict_counts.get('error', 0)}"
    )
    detail = []
    for stage in (envelope.get("stages") or [])[:4]:
        detail.append(
            f"{stage.get('name', '?')}: {stage.get('verdict', '?')} "
            f"({stage.get('summary', '')})"[:120]
        )
    return verdict, summary, detail


def _parse_mcp_smoke(envelope: dict[str, Any]) -> tuple[str, str, list[str]]:
    """Parse ``hackerman-mcp-smoke-test --json`` envelope."""
    all_passed = envelope.get("all_passed")
    total = envelope.get("callables_total")
    passed = envelope.get("callables_passed")
    failed = envelope.get("callables_failed")
    if total is None:
        results = envelope.get("results") or []
        total = len(results)
        passed = sum(1 for r in results if r.get("passed"))
        failed = total - passed
        all_passed = failed == 0
    verdict = VERDICT_PASS if all_passed else VERDICT_FAIL
    summary = f"callables={total} pass={passed} fail={failed}"
    detail = []
    for res in (envelope.get("results") or [])[:4]:
        flag = "ok" if res.get("passed") else "FAIL"
        detail.append(
            f"{res.get('name', '?')}: {flag} ({res.get('elapsed_seconds', 0):.2f}s)"[:120]
        )
    return verdict, summary, detail


# ---------------------------------------------------------------------------
# Default registry. argv_builder receives the dashboard context (kwargs)
# so the MCP smoke axis can plumb the --timeout knob through.
# ---------------------------------------------------------------------------


def _corpus_argv(ctx: dict[str, Any]) -> list[str]:
    return [sys.executable, str(REPO_ROOT / "tools" / "hackerman-corpus-stats.py"), "--json"]


def _gates_argv(ctx: dict[str, Any]) -> list[str]:
    return [sys.executable, str(REPO_ROOT / "tools" / "hackerman-gates-status.py"), "--json"]


def _integrity_argv(ctx: dict[str, Any]) -> list[str]:
    return [sys.executable, str(REPO_ROOT / "tools" / "hackerman-integrity-check.py"), "--json"]


def _mcp_smoke_argv(ctx: dict[str, Any]) -> list[str]:
    timeout = int(ctx.get("mcp_smoke_timeout") or DEFAULT_MCP_SMOKE_TIMEOUT_SECONDS)
    return [
        sys.executable,
        str(REPO_ROOT / "tools" / "hackerman-mcp-smoke-test.py"),
        "--json",
        "--timeout",
        str(timeout),
    ]


HACKERMAN_DASHBOARD_AXES: list[AxisSpec] = [
    AxisSpec(
        name="corpus",
        description="hackerman-corpus-stats: corpus shape + tier/acceptance gates.",
        argv_builder=_corpus_argv,
        result_parser=_parse_corpus_stats,
        timeout_seconds=180,
    ),
    AxisSpec(
        name="gates",
        description="hackerman-gates-status: aggregated pre-submit hackerman gates.",
        argv_builder=_gates_argv,
        result_parser=_parse_gates_status,
        timeout_seconds=180,
    ),
    AxisSpec(
        name="integrity",
        description="hackerman-integrity-check: full corpus integrity stages.",
        argv_builder=_integrity_argv,
        result_parser=_parse_integrity_check,
        timeout_seconds=600,
    ),
    AxisSpec(
        name="mcp-smoke",
        description="hackerman-mcp-smoke-test: Wave-1 MCP callable smoke test.",
        argv_builder=_mcp_smoke_argv,
        result_parser=_parse_mcp_smoke,
        timeout_seconds=300,
    ),
]


# ---------------------------------------------------------------------------
# Core runner.
# ---------------------------------------------------------------------------


def run_axis(spec: AxisSpec, ctx: dict[str, Any]) -> AxisResult:
    """Execute one axis and return its normalised result."""
    argv = spec.argv_builder(ctx)
    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=spec.timeout_seconds,
            cwd=str(REPO_ROOT),
            check=False,
        )
    except FileNotFoundError as exc:
        return AxisResult(
            name=spec.name,
            verdict=VERDICT_MISSING,
            summary=f"tool not found: {exc}",
            detail=[],
            rc=127,
            elapsed_seconds=time.monotonic() - start,
            envelope=None,
            error=str(exc),
        )
    except subprocess.TimeoutExpired as exc:
        return AxisResult(
            name=spec.name,
            verdict=VERDICT_ERROR,
            summary=f"timeout after {spec.timeout_seconds}s",
            detail=[],
            rc=124,
            elapsed_seconds=time.monotonic() - start,
            envelope=None,
            error=str(exc),
        )

    elapsed = time.monotonic() - start
    stdout = proc.stdout or ""
    try:
        envelope = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError as exc:
        return AxisResult(
            name=spec.name,
            verdict=VERDICT_ERROR,
            summary=f"json decode error: {exc.msg}",
            detail=[stdout[:200]] if stdout else [],
            rc=proc.returncode,
            elapsed_seconds=elapsed,
            envelope=None,
            error=str(exc),
        )

    if proc.returncode != 0:
        # Upstream tool failed. Still try parser so we can show context.
        try:
            verdict, summary, detail = spec.result_parser(envelope)
        except Exception:  # noqa: BLE001
            verdict, summary, detail = VERDICT_FAIL, f"rc={proc.returncode}", []
        # rc != 0 always demotes to FAIL unless parser already said worse.
        if verdict == VERDICT_PASS:
            verdict = VERDICT_FAIL
        return AxisResult(
            name=spec.name,
            verdict=verdict,
            summary=f"rc={proc.returncode} {summary}",
            detail=detail,
            rc=proc.returncode,
            elapsed_seconds=elapsed,
            envelope=envelope,
            error=(proc.stderr or "").strip()[:200],
        )

    try:
        verdict, summary, detail = spec.result_parser(envelope)
    except Exception as exc:  # noqa: BLE001
        return AxisResult(
            name=spec.name,
            verdict=VERDICT_ERROR,
            summary=f"parser error: {exc}",
            detail=[],
            rc=proc.returncode,
            elapsed_seconds=elapsed,
            envelope=envelope,
            error=str(exc),
        )

    return AxisResult(
        name=spec.name,
        verdict=verdict,
        summary=summary,
        detail=detail,
        rc=proc.returncode,
        elapsed_seconds=elapsed,
        envelope=envelope,
        error="",
    )


def run_dashboard(
    axes: list[AxisSpec] | None = None,
    *,
    ctx: dict[str, Any] | None = None,
    only: set[str] | None = None,
) -> list[AxisResult]:
    """Run every axis in declaration order; one failure does not short-circuit."""
    axes = axes if axes is not None else HACKERMAN_DASHBOARD_AXES
    ctx = ctx or {}
    out: list[AxisResult] = []
    for spec in axes:
        if only and spec.name not in only:
            continue
        out.append(run_axis(spec, ctx))
    return out


# ---------------------------------------------------------------------------
# Rendering.
# ---------------------------------------------------------------------------


def _colourise(text: str, colour: str | None, enabled: bool) -> str:
    if not enabled or not colour:
        return text
    code = _ANSI.get(colour, "")
    if not code:
        return text
    return f"{code}{text}{_ANSI['reset']}"


def overall_verdict(results: list[AxisResult]) -> str:
    """Roll axis verdicts up into a single overall verdict."""
    if not results:
        return VERDICT_ERROR
    if any(r.verdict == VERDICT_FAIL for r in results):
        return VERDICT_FAIL
    if any(r.verdict in (VERDICT_MISSING, VERDICT_ERROR) for r in results):
        return VERDICT_FAIL
    return VERDICT_PASS


def render_human(
    results: list[AxisResult],
    *,
    generated_at: str,
    colour_enabled: bool,
    max_lines: int = DEFAULT_MAX_LINES,
) -> str:
    """Render the compact human dashboard.

    Output is hard-capped at ``max_lines``. Each axis contributes:

      <one-line status header>
        <up to 4 detail lines>

    Plus 4 framing lines (top banner, subtitle, blank line, footer).
    The 80-line default is comfortably enough for the 4 Wave-1 axes
    plus 4-line detail blocks (~24 lines total).
    """
    lines: list[str] = []
    title = "hackerman health dashboard"
    lines.append(_colourise(f"=== {title} ===", "bold", colour_enabled))
    lines.append(_colourise(f"generated_at: {generated_at}", "grey", colour_enabled))
    lines.append("")
    for res in results:
        colour = _VERDICT_COLOUR.get(res.verdict, "grey")
        head = (
            f"[{res.verdict.upper():<7}] {res.name:<10} "
            f"({res.elapsed_seconds:.2f}s) {res.summary}"
        )
        lines.append(_colourise(head, colour, colour_enabled))
        for d in res.detail[:4]:
            lines.append("    " + d)
        if res.error:
            lines.append(_colourise(f"    error: {res.error[:120]}", "yellow", colour_enabled))
    lines.append("")
    overall = overall_verdict(results)
    overall_colour = _VERDICT_COLOUR.get(overall, "grey")
    lines.append(
        _colourise(
            f"overall: {overall.upper()} ({len(results)} axes)",
            overall_colour,
            colour_enabled,
        )
    )
    # Hard cap. Truncate from the bottom with a marker.
    if len(lines) > max_lines:
        truncated = max_lines - 1
        lines = lines[:truncated]
        lines.append(
            _colourise(
                f"... output truncated to {max_lines} lines", "yellow", colour_enabled
            )
        )
    return "\n".join(lines)


def render_envelope(
    results: list[AxisResult],
    *,
    generated_at: str,
) -> dict[str, Any]:
    """Return the JSON envelope for downstream tooling."""
    overall = overall_verdict(results)
    verdict_counts: dict[str, int] = {}
    for r in results:
        verdict_counts[r.verdict] = verdict_counts.get(r.verdict, 0) + 1
    return {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "axis_count": len(results),
        "overall_verdict": overall,
        "verdict_counts": verdict_counts,
        "axes": [r.to_dict() for r in results],
    }


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _resolve_generated_at(arg_value: str | None) -> str:
    if arg_value:
        return arg_value
    env_value = os.environ.get("AUDITOOOR_HEALTH_DASHBOARD_GENERATED_AT")
    if env_value:
        return env_value
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_colour_enabled(
    *, no_color: bool, force_color: bool, stream
) -> bool:
    if force_color:
        return True
    if no_color:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Hackerman health dashboard (Wave-1, PR #726).",
    )
    p.add_argument(
        "--axis",
        action="append",
        default=None,
        help="Restrict execution to this axis (repeatable). Default: all.",
    )
    p.add_argument(
        "--mcp-smoke-timeout",
        type=int,
        default=DEFAULT_MCP_SMOKE_TIMEOUT_SECONDS,
        help=(
            "Per-callable timeout (seconds) for the mcp-smoke axis. "
            f"Default {DEFAULT_MCP_SMOKE_TIMEOUT_SECONDS}."
        ),
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit the dashboard envelope as JSON on stdout.",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when overall verdict != pass.",
    )
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colour output.")
    p.add_argument("--force-color", action="store_true", help="Force ANSI colour output.")
    p.add_argument(
        "--max-lines",
        type=int,
        default=DEFAULT_MAX_LINES,
        help=f"Hard cap on rendered human-output lines (default {DEFAULT_MAX_LINES}).",
    )
    p.add_argument(
        "--generated-at",
        default=None,
        help=(
            "Pin generated_at (ISO-8601 UTC). Also honoured via "
            "env AUDITOOOR_HEALTH_DASHBOARD_GENERATED_AT."
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    ns = parser.parse_args(argv)
    only = set(ns.axis) if ns.axis else None
    if only:
        valid = {a.name for a in HACKERMAN_DASHBOARD_AXES}
        unknown = only - valid
        if unknown:
            print(
                f"unknown axis(es): {sorted(unknown)}; valid={sorted(valid)}",
                file=sys.stderr,
            )
            return 2
    ctx = {"mcp_smoke_timeout": ns.mcp_smoke_timeout}
    results = run_dashboard(only=only, ctx=ctx)
    generated_at = _resolve_generated_at(ns.generated_at)
    if ns.json:
        envelope = render_envelope(results, generated_at=generated_at)
        json.dump(envelope, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        colour_enabled = _resolve_colour_enabled(
            no_color=ns.no_color, force_color=ns.force_color, stream=sys.stdout
        )
        out = render_human(
            results,
            generated_at=generated_at,
            colour_enabled=colour_enabled,
            max_lines=ns.max_lines,
        )
        print(out)
    overall = overall_verdict(results)
    if ns.strict and overall != VERDICT_PASS:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
