#!/usr/bin/env python3
"""cost-telemetry.py — PR 210: per-stage duration + coarse cost estimate.

This module provides a context-manager API that any engage.py stage can
wrap itself in, writing a per-stage JSON telemetry file under:

    <workspace>/cost_runs/<run_ts>/stage_<stage_name>.json

Each file records `{stage, started_at, duration_s, est_tokens, est_cost_usd,
model, cost_source}`. An operator-facing summarizer (`summarize_workspace`)
aggregates every stage file under `<workspace>/cost_runs/` into a total
duration + total cost breakdown.

Truth-audit discipline (per v2 doctrine):

- Every cost-bearing field is named `est_*`. This is an estimate; never a
  precise bill. A stage with no rate-card match records `est_cost_usd=None`
  and sets `cost_source="walltime-only"` rather than silently reporting
  `$0.00` (which would let stale rate-card entries look truthful).
- Non-LLM stages (subprocess tools) pass `model=None`, record walltime only,
  and set `est_cost_usd=0` with `cost_source="subprocess"` — these are
  genuinely zero-cost for the LLM budget.
- The rate card is a hard-coded JSON file (`tools/cost_rate_card.json`) and
  operators can override via `COST_RATE_CARD_PATH` env var to run offline
  sensitivity analyses without editing repo files.
- Cost telemetry is **advisory only**; it MUST NOT gate submissions or be
  cited as evidence inside a finding.

CLI:

    python3 tools/cost-telemetry.py --summarize <workspace> [--json]

Stdlib only. Never touches the network.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

HERE = Path(__file__).resolve().parent
DEFAULT_RATE_CARD = HERE / "cost_rate_card.json"


# --------------------------------------------------------------------------- #
# Rate card
# --------------------------------------------------------------------------- #

def _rate_card_path() -> Path:
    override = os.environ.get("COST_RATE_CARD_PATH")
    if override:
        return Path(override).expanduser()
    return DEFAULT_RATE_CARD


def load_rate_card(path: Path | None = None) -> dict[str, Any]:
    """Load the per-model rate card. Returns an empty models dict on failure."""
    p = path or _rate_card_path()
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return {"models": {}}
    if not isinstance(data, dict) or not isinstance(data.get("models"), dict):
        return {"models": {}}
    return data


def _lookup_model(card: dict[str, Any], model: str | None) -> dict[str, float] | None:
    """Return the rate entry for `model`, falling back to `default` if present."""
    if model is None:
        return None
    models = card.get("models", {})
    # Exact match first, then prefix (e.g. "sonnet-4.5-20251022" -> "sonnet-4.5" -> "sonnet").
    if model in models:
        return models[model]
    for key in sorted(models.keys(), key=len, reverse=True):
        if key == "default":
            continue
        if model.startswith(key):
            return models[key]
    if "default" in models:
        return models["default"]
    return None


# --------------------------------------------------------------------------- #
# Cost computation
# --------------------------------------------------------------------------- #

def estimate_cost_usd(
    model: str | None,
    est_tokens: dict[str, int] | None,
    rate_card: dict[str, Any] | None = None,
) -> tuple[float | None, str]:
    """Return (est_cost_usd, cost_source).

    - Non-LLM stage (model is None): (0.0, "subprocess").
    - LLM stage without est_tokens: (None, "walltime-only"). Never $0 — that
      would hide missing-data bugs behind a plausible zero.
    - LLM stage with est_tokens but no rate match: (None, "walltime-only").
    - LLM stage with rate match: (usd, "rate-card").
    """
    if model is None:
        return 0.0, "subprocess"
    if not est_tokens:
        return None, "walltime-only"

    card = rate_card if rate_card is not None else load_rate_card()
    entry = _lookup_model(card, model)
    if entry is None:
        return None, "walltime-only"

    in_tok = int(est_tokens.get("input", 0) or 0)
    out_tok = int(est_tokens.get("output", 0) or 0)
    in_rate = float(entry.get("input_per_mtok_usd", 0.0) or 0.0)
    out_rate = float(entry.get("output_per_mtok_usd", 0.0) or 0.0)
    usd = (in_tok / 1_000_000.0) * in_rate + (out_tok / 1_000_000.0) * out_rate
    return usd, "rate-card"


# --------------------------------------------------------------------------- #
# Run-scoped context
# --------------------------------------------------------------------------- #

_ACTIVE_RUN_TS: str | None = None


def _utc_now_ts() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def start_run(ts: str | None = None) -> str:
    """Pin a single run timestamp so all stages in one engage.py invocation
    land under the same <ws>/cost_runs/<ts>/ dir.

    Calling this is optional — if not called, each stage falls back to its own
    start time (still correct, but the directory will be per-stage)."""
    global _ACTIVE_RUN_TS
    _ACTIVE_RUN_TS = ts or _utc_now_ts()
    return _ACTIVE_RUN_TS


def current_run_ts() -> str:
    return _ACTIVE_RUN_TS or _utc_now_ts()


def reset_run() -> None:
    """Clear the pinned run timestamp (for tests)."""
    global _ACTIVE_RUN_TS
    _ACTIVE_RUN_TS = None


# --------------------------------------------------------------------------- #
# record_stage context manager
# --------------------------------------------------------------------------- #

class _StageRecorder:
    """Mutable handle yielded inside `record_stage`; lets the wrapped code
    update est_tokens mid-run (e.g. once an LLM response returns)."""

    def __init__(self, stage: str, model: str | None,
                 est_tokens: dict[str, int] | None) -> None:
        self.stage = stage
        self.model = model
        self.est_tokens: dict[str, int] | None = dict(est_tokens) if est_tokens else None

    def set_tokens(self, input: int, output: int) -> None:
        self.est_tokens = {"input": int(input), "output": int(output)}

    def set_model(self, model: str | None) -> None:
        self.model = model


@contextlib.contextmanager
def record_stage(
    stage_name: str,
    workspace: Path | str,
    model: str | None = None,
    est_tokens: dict[str, int] | None = None,
    rate_card_path: Path | None = None,
) -> Iterator[_StageRecorder]:
    """Context manager: time a stage, compute cost, write JSON artifact.

    Usage:

        with record_stage("scan", ws) as rec:
            ...  # run the stage
            # (optional, for LLM stages:) rec.set_tokens(1000, 500)

    Never raises — artifact-write failures are swallowed with a warning on
    stderr so that cost telemetry cannot break the engagement pipeline.
    """
    ws = Path(workspace).expanduser()
    recorder = _StageRecorder(stage_name, model, est_tokens)
    started_at = datetime.now(tz=timezone.utc).isoformat()
    t0 = time.time()
    try:
        yield recorder
    finally:
        duration_s = time.time() - t0
        _emit_stage_artifact(ws, recorder, started_at, duration_s, rate_card_path)


def _emit_stage_artifact(
    ws: Path,
    recorder: "_StageRecorder",
    started_at: str,
    duration_s: float,
    rate_card_path: Path | None,
) -> None:
    """Write one stage_<name>.json artifact. Never raises — warnings only."""
    run_ts = current_run_ts()
    run_dir = ws / "cost_runs" / run_ts
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"[cost-telemetry] WARN mkdir {run_dir}: {e}", file=sys.stderr)
        return

    card = load_rate_card(rate_card_path) if rate_card_path else load_rate_card()
    est_cost, cost_source = estimate_cost_usd(
        recorder.model, recorder.est_tokens, card)

    payload = {
        "stage": recorder.stage,
        "started_at": started_at,
        "duration_s": round(duration_s, 6),
        "est_tokens": recorder.est_tokens,
        "est_cost_usd": est_cost,
        "model": recorder.model,
        "cost_source": cost_source,
    }
    artifact = run_dir / f"stage_{_safe_stage_filename(recorder.stage)}.json"
    try:
        # If two stages share a name inside one run, append a counter.
        if artifact.exists():
            i = 2
            while (run_dir / f"stage_{_safe_stage_filename(recorder.stage)}_{i}.json").exists():
                i += 1
            artifact = run_dir / f"stage_{_safe_stage_filename(recorder.stage)}_{i}.json"
        artifact.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    except OSError as e:
        print(f"[cost-telemetry] WARN write {artifact}: {e}", file=sys.stderr)


def _safe_stage_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in name)


# --------------------------------------------------------------------------- #
# Summarizer
# --------------------------------------------------------------------------- #

def summarize_workspace(workspace: Path | str) -> dict[str, Any]:
    """Aggregate every stage_*.json file under <ws>/cost_runs/ into a single
    dict of {total_duration_s, total_est_cost_usd, stage_count, runs[],
    per_stage{}, cost_source_mix}.

    Tolerant: missing cost_runs/ → empty summary. Malformed JSON → skipped.
    Returns a JSON-serializable dict with deterministic key order.
    """
    ws = Path(workspace).expanduser()
    root = ws / "cost_runs"
    empty: dict[str, Any] = {
        "workspace": str(ws),
        "total_duration_s": 0.0,
        "total_est_cost_usd": 0.0,
        "cost_is_partial": False,
        "stage_count": 0,
        "runs": [],
        "per_stage": {},
        "cost_source_mix": {},
    }
    if not root.exists() or not root.is_dir():
        return empty

    total_duration = 0.0
    total_cost = 0.0
    cost_partial = False
    per_stage: dict[str, dict[str, Any]] = {}
    source_mix: dict[str, int] = {}
    stage_count = 0
    runs: set[str] = set()

    for stage_file in sorted(root.rglob("stage_*.json")):
        try:
            payload = json.loads(stage_file.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        stage = str(payload.get("stage") or stage_file.stem)
        duration = float(payload.get("duration_s") or 0.0)
        cost = payload.get("est_cost_usd")
        source = str(payload.get("cost_source") or "unknown")

        total_duration += duration
        if cost is None:
            cost_partial = True
        else:
            total_cost += float(cost)
        stage_count += 1
        source_mix[source] = source_mix.get(source, 0) + 1

        # Record the run directory (parent of the stage file).
        try:
            runs.add(stage_file.parent.name)
        except Exception:
            pass

        slot = per_stage.setdefault(stage, {
            "count": 0,
            "total_duration_s": 0.0,
            "total_est_cost_usd": 0.0,
            "cost_is_partial": False,
        })
        slot["count"] += 1
        slot["total_duration_s"] += duration
        if cost is None:
            slot["cost_is_partial"] = True
        else:
            slot["total_est_cost_usd"] += float(cost)

    # Round for JSON-friendliness.
    for slot in per_stage.values():
        slot["total_duration_s"] = round(slot["total_duration_s"], 6)
        slot["total_est_cost_usd"] = round(slot["total_est_cost_usd"], 6)

    return {
        "workspace": str(ws),
        "total_duration_s": round(total_duration, 6),
        "total_est_cost_usd": round(total_cost, 6),
        "cost_is_partial": cost_partial,
        "stage_count": stage_count,
        "runs": sorted(runs),
        "per_stage": dict(sorted(per_stage.items())),
        "cost_source_mix": dict(sorted(source_mix.items())),
    }


# --------------------------------------------------------------------------- #
# Render helper (also used by outcome-telemetry.py)
# --------------------------------------------------------------------------- #

def render_summary_markdown(summary: dict[str, Any],
                            cost_per_finding: float | None = None,
                            filed_findings: int | None = None) -> str:
    """Render a 1-page Markdown block for an operator. Safe to drop into the
    outcome-telemetry dashboard."""
    lines: list[str] = []
    lines.append("## Cost Summary")
    lines.append("")
    if summary.get("stage_count", 0) == 0:
        lines.append("- _no cost_runs/ telemetry found for this workspace_")
        lines.append("")
        return "\n".join(lines)

    total_cost = summary.get("total_est_cost_usd", 0.0)
    total_dur = summary.get("total_duration_s", 0.0)
    partial = summary.get("cost_is_partial", False)
    partial_note = " (partial — some stages walltime-only)" if partial else ""

    lines.append(f"- Workspace: `{summary.get('workspace', '?')}`")
    lines.append(f"- Runs: {len(summary.get('runs', []) or [])}")
    lines.append(f"- Stages recorded: {summary.get('stage_count', 0)}")
    lines.append(f"- Total walltime: {total_dur:.1f}s ({total_dur / 60.0:.1f} min)")
    lines.append(f"- Total est cost: ${total_cost:.4f}{partial_note}")
    if cost_per_finding is not None and filed_findings is not None and filed_findings > 0:
        lines.append(
            f"- Est cost / filed finding: ${cost_per_finding:.4f} "
            f"(over {filed_findings} filed)"
        )
    elif filed_findings == 0:
        lines.append("- Est cost / filed finding: n/a (no findings filed yet)")
    lines.append("")

    per_stage = summary.get("per_stage") or {}
    if per_stage:
        lines.append("| Stage | Runs | Walltime (s) | Est Cost (USD) |")
        lines.append("|---|---:|---:|---:|")
        for name, slot in per_stage.items():
            partial_flag = "*" if slot.get("cost_is_partial") else ""
            lines.append(
                f"| {name} | {slot.get('count', 0)} | "
                f"{slot.get('total_duration_s', 0.0):.1f} | "
                f"${slot.get('total_est_cost_usd', 0.0):.4f}{partial_flag} |"
            )
        if partial:
            lines.append("")
            lines.append("_`*` = this stage had one or more entries with no cost estimate "
                         "(model known but est_tokens missing). Treat the cost total as a "
                         "lower bound, not a precise bill._")
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="PR 210 cost telemetry summarizer (advisory, not proof).",
    )
    ap.add_argument("--summarize", metavar="WORKSPACE", required=True,
                    help="Workspace directory to summarize.")
    ap.add_argument("--json", action="store_true",
                    help="Emit JSON instead of Markdown.")
    args = ap.parse_args(argv)

    ws = Path(args.summarize).expanduser().resolve()
    summary = summarize_workspace(ws)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(render_summary_markdown(summary), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
