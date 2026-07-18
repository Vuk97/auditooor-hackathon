#!/usr/bin/env python3
# r36-rebuttal: lane-RULE-65-CALIBRATION declared in .auditooor/agent_pathspec.json
"""deepseek-calibrate.py - R65 paired-comparison calibration runner.

For a given task_id, fires N=10 representative items on BOTH
`deepseek-flash` and `deepseek-pro`, spawns a Claude verifier sub-agent
to score each output 1-5 against the per-task-class rubric, then
persists the paired-comparison decision to
`reference/deepseek_task_routing.json`.

The calibration sub-batch is intentionally CHEAP (~$0.20 typical for
N=10, 2 models) so it can run as a prerequisite to a $1+ full-spend
dispatch. R65 gates the full spend on the freshness of this routing
entry.

CLI
---
    python3 tools/deepseek-calibrate.py --task-id <TOK-X>
        [--sample-size 10]
        [--max-cost-usd 1]
        [--rubric <path>]
        [--candidate-models deepseek-flash,deepseek-pro]
        [--routing-json <path>]
        [--sample-source <path>]
        [--verifier claude-sonnet-4-5]
        [--mock]                  # mock fanout + verifier (offline tests)
        [--dry-run]               # print plan but do not fire
        [--json]

Output JSON shape (schema auditooor.deepseek_calibrate.v1):

    {
      "schema": "auditooor.deepseek_calibrate.v1",
      "task_id": "TOK-B-CL",
      "task_class": "cross-language-invariant-lift",
      "calibration_date": "2026-05-26",
      "sample_size": 10,
      "candidate_models": ["deepseek-flash", "deepseek-pro"],
      "flash_score": 3.2,
      "pro_score": 4.7,
      "winner": "deepseek-pro",
      "confidence": 0.85,
      "decision_rationale": "Pro 5/5 idiomatic Rust...",
      "ratio_flash_over_pro": 0.68,
      "rubric_path": "reference/deepseek_rubrics/tok-b-cl.md",
      "cost_usd_per_item_flash": 0.005,
      "cost_usd_per_item_pro": 0.018,
      "calibration_cost_usd": 0.23,
      "evidence_dir": "reference/deepseek_calibration_runs/TOK-B-CL/2026-05-26/",
      "verdict": "calibration-complete"
    }

In --mock mode the tool fabricates plausible paired outputs from
canned-by-task-id fixtures, runs the rubric-scoring pipeline against the
fakes, and writes a deterministic routing.json entry. Live calibration
runs are guarded by NOT --mock (DEEPSEEK_LIVE_TEST is not consumed here;
the calibrator itself is the "live" path).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.deepseek_calibrate.v1"

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_ROUTING_JSON = _REPO_ROOT / "reference" / "deepseek_task_routing.json"
_RUBRIC_DIR = _REPO_ROOT / "reference" / "deepseek_rubrics"
_EVIDENCE_ROOT = _REPO_ROOT / "reference" / "deepseek_calibration_runs"

# Pricing in USD per 1K tokens (approximate, public list pricing 2026-05).
_PRICE_PER_1K = {
    "deepseek-flash": {"in": 0.00014, "out": 0.00028},
    "deepseek-pro": {"in": 0.00056, "out": 0.00224},
}

# Decision thresholds (R65 doctrine).
_FLASH_WINS_RATIO_THRESHOLD = 0.80   # Flash >= 80% of Pro on rubric
_PRO_DECISIVE_RATIO_THRESHOLD = 0.65  # Flash < 65% of Pro => Pro decisive
_FLASH_COST_MULTIPLE_THRESHOLD = 0.5  # Flash cost must be < 50% of Pro

# Task-class mapping (task_id -> task_class + rubric file).
_TASK_CLASS_MAP = {
    "TOK-A": {"class": "rationale-mining", "rubric": "tok-a-exp.md"},
    "TOK-A-EXP": {"class": "rationale-mining", "rubric": "tok-a-exp.md"},
    "TOK-B": {"class": "cross-language-invariant-lift", "rubric": "tok-b-cl.md"},
    "TOK-B-CL": {"class": "cross-language-invariant-lift", "rubric": "tok-b-cl.md"},
    "TOK-C": {"class": "per-workspace-hypothesis-gen", "rubric": "tok-c-ws.md"},
    "TOK-C-WS": {"class": "per-workspace-hypothesis-gen", "rubric": "tok-c-ws.md"},
    "TOK-D": {"class": "adversarial-triager-persona", "rubric": "tok-d.md"},
    "TOK-T": {"class": "triager-pattern-mining", "rubric": "tok-t.md"},
}


def resolve_task_class(task_id: str) -> dict[str, str]:
    """Map task_id to {class, rubric} via static table."""
    key = task_id.strip().upper()
    if key in _TASK_CLASS_MAP:
        return _TASK_CLASS_MAP[key]
    # Try prefix match (e.g. TOK-B-FOO -> TOK-B).
    for prefix in ("TOK-B-CL", "TOK-B", "TOK-A-EXP", "TOK-A", "TOK-C-WS",
                   "TOK-C", "TOK-D", "TOK-T"):
        if key.startswith(prefix):
            return _TASK_CLASS_MAP[prefix]
    return {"class": "unknown", "rubric": ""}


def load_rubric(rubric_path: Path) -> dict[str, Any]:
    """Parse the rubric markdown to extract scoring dimensions.

    Rubric files use simple format:
        # Rubric: <task class>
        ...
        ## Dimensions
        - <dim-1>: <description>
        - <dim-2>: <description>
        ...

    Returns {title, dimensions: [{name, description}], raw}.
    """
    if not rubric_path.exists():
        return {"title": "<missing>", "dimensions": [], "raw": "",
                "_error": f"rubric not found: {rubric_path}"}
    raw = rubric_path.read_text(encoding="utf-8")
    title = ""
    dimensions: list[dict[str, str]] = []
    in_dims = False
    for line in raw.splitlines():
        if line.startswith("# Rubric") or line.startswith("# "):
            if not title:
                title = line.lstrip("#").strip()
        if line.strip().lower().startswith("## dimensions") or \
           line.strip().lower().startswith("## scoring dimensions"):
            in_dims = True
            continue
        if line.startswith("## ") and in_dims:
            # Next section ends the dimensions block.
            in_dims = False
        if in_dims and line.strip().startswith("- "):
            body = line.strip()[2:].strip()
            if ":" in body:
                name, desc = body.split(":", 1)
                dimensions.append({"name": name.strip(),
                                   "description": desc.strip()})
            else:
                dimensions.append({"name": body, "description": ""})
    return {"title": title or "<untitled>",
            "dimensions": dimensions, "raw": raw}


def _mock_paired_outputs(task_id: str, sample_size: int) -> list[dict[str, Any]]:
    """Return canned paired outputs for offline tests. Deterministic by
    task_id."""
    items = []
    # Deterministic scoring profile per task. The mock encodes the
    # 2026-05-26 anchor: TOK-B-CL Pro decisively beats Flash.
    profiles = {
        "TOK-B-CL": {"flash_avg": 3.2, "pro_avg": 4.7},
        "TOK-B": {"flash_avg": 3.2, "pro_avg": 4.7},
        "TOK-A-EXP": {"flash_avg": 4.1, "pro_avg": 4.5},
        "TOK-A": {"flash_avg": 4.1, "pro_avg": 4.5},
        "TOK-D": {"flash_avg": 4.0, "pro_avg": 4.2},
        "TOK-T": {"flash_avg": 3.8, "pro_avg": 4.4},
        "TOK-C-WS": {"flash_avg": 3.6, "pro_avg": 4.6},
        "TOK-C": {"flash_avg": 3.6, "pro_avg": 4.6},
    }
    key = task_id.strip().upper()
    profile = profiles.get(key)
    if profile is None:
        # Default neutral profile.
        for prefix, prof in profiles.items():
            if key.startswith(prefix):
                profile = prof
                break
    if profile is None:
        profile = {"flash_avg": 3.5, "pro_avg": 4.0}
    for i in range(sample_size):
        items.append({
            "item_idx": i,
            "prompt": f"<mock prompt {i} for {task_id}>",
            "flash_output": f"<mock flash output {i}>",
            "pro_output": f"<mock pro output {i}>",
            "flash_score_per_dim": [profile["flash_avg"]] * 5,
            "pro_score_per_dim": [profile["pro_avg"]] * 5,
            "input_tokens": 1200,
            "flash_output_tokens": 400,
            "pro_output_tokens": 500,
        })
    return items


def _compute_costs(items: list[dict[str, Any]]) -> dict[str, float]:
    """Compute aggregate calibration cost from per-item token counts."""
    flash_in = sum(it["input_tokens"] for it in items)
    flash_out = sum(it["flash_output_tokens"] for it in items)
    pro_in = sum(it["input_tokens"] for it in items)
    pro_out = sum(it["pro_output_tokens"] for it in items)
    flash_cost = (flash_in / 1000.0 * _PRICE_PER_1K["deepseek-flash"]["in"]
                  + flash_out / 1000.0 * _PRICE_PER_1K["deepseek-flash"]["out"])
    pro_cost = (pro_in / 1000.0 * _PRICE_PER_1K["deepseek-pro"]["in"]
                + pro_out / 1000.0 * _PRICE_PER_1K["deepseek-pro"]["out"])
    n = max(1, len(items))
    return {
        "flash_cost_usd": flash_cost,
        "pro_cost_usd": pro_cost,
        "total_cost_usd": flash_cost + pro_cost,
        "cost_per_item_flash": flash_cost / n,
        "cost_per_item_pro": pro_cost / n,
    }


def aggregate_scores(items: list[dict[str, Any]]) -> dict[str, float]:
    """Mean rubric score across items per model."""
    if not items:
        return {"flash_score": 0.0, "pro_score": 0.0}
    flash_per_item = [sum(it["flash_score_per_dim"]) / max(1, len(it["flash_score_per_dim"]))
                      for it in items]
    pro_per_item = [sum(it["pro_score_per_dim"]) / max(1, len(it["pro_score_per_dim"]))
                    for it in items]
    flash_avg = sum(flash_per_item) / len(flash_per_item)
    pro_avg = sum(pro_per_item) / len(pro_per_item)
    return {
        "flash_score": round(flash_avg, 3),
        "pro_score": round(pro_avg, 3),
    }


def decide_winner(flash_score: float, pro_score: float,
                  cost_per_item_flash: float,
                  cost_per_item_pro: float) -> dict[str, Any]:
    """R65 decision rule. Returns dict with winner / confidence /
    rationale / ratio_flash_over_pro."""
    pro_safe = pro_score if pro_score > 0 else 0.001
    ratio = round(flash_score / pro_safe, 3)
    cost_safe = cost_per_item_pro if cost_per_item_pro > 0 else 0.001
    cost_ratio = cost_per_item_flash / cost_safe

    if ratio >= _FLASH_WINS_RATIO_THRESHOLD and \
       cost_ratio < _FLASH_COST_MULTIPLE_THRESHOLD:
        winner = "deepseek-flash"
        rationale = (
            f"Flash score {flash_score} >= {_FLASH_WINS_RATIO_THRESHOLD*100:.0f}% "
            f"of Pro ({pro_score}); Flash cost {cost_ratio*100:.1f}% of Pro; "
            f"Flash wins on cost-adjusted quality"
        )
        confidence = min(1.0, ratio)
    elif ratio < _PRO_DECISIVE_RATIO_THRESHOLD:
        winner = "deepseek-pro"
        rationale = (
            f"Flash score {flash_score} only {ratio*100:.0f}% of Pro "
            f"({pro_score}); Pro decisive on quality"
        )
        confidence = min(1.0, 1 - ratio)
    else:
        winner = "hybrid"
        rationale = (
            f"Flash {flash_score} vs Pro {pro_score} (ratio {ratio}); "
            f"hybrid recommended: Flash on bulk + Pro on top-N or borderline items"
        )
        confidence = round(0.5 + abs(ratio - 0.725) / 0.3, 2)
        confidence = max(0.0, min(1.0, confidence))

    return {
        "winner": winner,
        "confidence": round(confidence, 3),
        "decision_rationale": rationale,
        "ratio_flash_over_pro": ratio,
    }


def upsert_routing_entry(routing_path: Path,
                         entry: dict[str, Any]) -> dict[str, Any]:
    """Read routing.json, replace or append the entry for entry['task_id'],
    write back. Returns the resulting top-level routing dict."""
    if routing_path.exists():
        try:
            doc = json.loads(routing_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            doc = {"schema": "auditooor.deepseek_task_routing.v1",
                   "entries": []}
    else:
        doc = {"schema": "auditooor.deepseek_task_routing.v1",
               "entries": []}
    entries = doc.get("entries", [])
    if not isinstance(entries, list):
        entries = []
    needle = entry["task_id"].strip().upper()
    new_entries = [e for e in entries
                   if isinstance(e, dict)
                   and str(e.get("task_id", "")).strip().upper() != needle]
    new_entries.append(entry)
    doc["entries"] = new_entries
    doc["last_updated_utc"] = _dt.datetime.now(tz=_dt.timezone.utc).isoformat()
    routing_path.parent.mkdir(parents=True, exist_ok=True)
    routing_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return doc


def run_calibration(task_id: str,
                    sample_size: int,
                    max_cost_usd: float,
                    rubric_path: Path,
                    candidate_models: list[str],
                    routing_path: Path,
                    sample_source: Path | None,
                    verifier: str,
                    mock: bool,
                    dry_run: bool) -> dict[str, Any]:
    """End-to-end calibration. In mock mode skips live fanout +
    verifier, uses canned scores. Live mode is intentionally lightweight
    here; production live runs go through tools/llm-fanout-dispatcher.py
    plus a separate verifier sub-agent in a follow-up commit."""

    task_class = resolve_task_class(task_id)
    rubric = load_rubric(rubric_path) if rubric_path else {"dimensions": [], "title": "?"}

    if dry_run:
        plan = {
            "schema": SCHEMA,
            "task_id": task_id,
            "task_class": task_class["class"],
            "sample_size": sample_size,
            "candidate_models": candidate_models,
            "rubric_dimensions": [d["name"] for d in rubric.get("dimensions", [])],
            "estimated_max_cost_usd": max_cost_usd,
            "verdict": "dry-run-plan-only",
            "note": "no calls fired; no routing.json modified",
        }
        return plan

    if mock:
        items = _mock_paired_outputs(task_id, sample_size)
    else:
        # Live mode requires the operator to wire in
        # tools/llm-fanout-dispatcher.py for actual fanout AND
        # a Claude verifier sub-agent for scoring. The simplest live
        # path for this v1 ships a stub that fails closed unless the
        # operator passes --mock or provides a populated
        # AUDITOOOR_DEEPSEEK_CALIBRATE_LIVE_RUNNER env var pointing
        # to a custom runner script.
        live_runner = os.environ.get("AUDITOOOR_DEEPSEEK_CALIBRATE_LIVE_RUNNER", "")
        if not live_runner:
            return {
                "schema": SCHEMA,
                "task_id": task_id,
                "verdict": "error",
                "decision_rationale": (
                    "live mode requires AUDITOOOR_DEEPSEEK_CALIBRATE_LIVE_RUNNER env var "
                    "(path to a script that emits paired-output JSONL). "
                    "Re-run with --mock for offline calibration."
                ),
            }
        # In v1 we shell out to the live runner; out of scope to fully
        # implement here. The test suite uses --mock exclusively.
        return {
            "schema": SCHEMA,
            "task_id": task_id,
            "verdict": "error",
            "decision_rationale": (
                f"live runner '{live_runner}' not invoked in v1 stub; "
                "use --mock or wire the runner integration in a follow-up commit"
            ),
        }

    # Aggregate scores + costs.
    scores = aggregate_scores(items)
    cost_info = _compute_costs(items)
    decision = decide_winner(
        flash_score=scores["flash_score"],
        pro_score=scores["pro_score"],
        cost_per_item_flash=cost_info["cost_per_item_flash"],
        cost_per_item_pro=cost_info["cost_per_item_pro"],
    )

    # Persist evidence (per-item paired outputs + scores).
    today_str = _dt.date.today().isoformat()
    evidence_dir = (_EVIDENCE_ROOT / task_id / today_str)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_dir / "paired_outputs.jsonl"
    with evidence_path.open("w", encoding="utf-8") as fh:
        for it in items:
            fh.write(json.dumps(it, separators=(",", ":")) + "\n")

    entry = {
        "task_id": task_id.strip().upper(),
        "task_class": task_class["class"],
        "calibration_date": today_str,
        "sample_size": sample_size,
        "rubric_path": str(rubric_path.relative_to(_REPO_ROOT))
                       if rubric_path.exists() else "",
        "candidate_models": candidate_models,
        "flash_score": scores["flash_score"],
        "pro_score": scores["pro_score"],
        "winner": decision["winner"],
        "confidence": decision["confidence"],
        "decision_rationale": decision["decision_rationale"],
        "ratio_flash_over_pro": decision["ratio_flash_over_pro"],
        "cost_usd_per_item_flash": round(cost_info["cost_per_item_flash"], 6),
        "cost_usd_per_item_pro": round(cost_info["cost_per_item_pro"], 6),
        "calibration_cost_usd": round(cost_info["total_cost_usd"], 4),
        "evidence_dir": str(evidence_dir.relative_to(_REPO_ROOT)),
        "verifier_model": verifier,
        "ts_utc": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
    }

    upsert_routing_entry(routing_path, entry)

    result = {**entry, "schema": SCHEMA, "verdict": "calibration-complete"}
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="R65 calibration runner. Paired-comparison sub-batch "
                    "writes a routing.json entry that gates full-budget "
                    "dispatches.",
    )
    parser.add_argument("--task-id", required=True,
                        help="Task identifier, e.g. TOK-B-CL.")
    parser.add_argument("--sample-size", type=int, default=10,
                        help="Number of paired items per model (default 10).")
    parser.add_argument("--max-cost-usd", type=float, default=1.0,
                        help="Cost ceiling for the calibration run (default $1).")
    parser.add_argument("--rubric", type=Path, default=None,
                        help="Override path to rubric file. Defaults to "
                             "reference/deepseek_rubrics/<class>.md.")
    parser.add_argument("--candidate-models", type=str,
                        default="deepseek-flash,deepseek-pro",
                        help="Comma-separated candidate model list "
                             "(default: deepseek-flash,deepseek-pro).")
    parser.add_argument("--routing-json", type=Path,
                        default=_DEFAULT_ROUTING_JSON,
                        help="Path to routing.json output.")
    parser.add_argument("--sample-source", type=Path, default=None,
                        help="Optional JSONL source of task-class items "
                             "for live mode.")
    parser.add_argument("--verifier", type=str, default="claude-sonnet-4-5",
                        help="Verifier model id (mock mode reports this "
                             "without invoking).")
    parser.add_argument("--mock", action="store_true",
                        help="Use canned paired outputs (no live calls).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print plan only; do not fire calls or write routing.json.")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON output.")
    args = parser.parse_args(argv)

    # Resolve rubric path.
    if args.rubric:
        rubric_path = args.rubric
    else:
        cls = resolve_task_class(args.task_id)
        rubric_path = _RUBRIC_DIR / cls["rubric"] if cls["rubric"] else _RUBRIC_DIR / "unknown.md"

    candidate_models = [m.strip() for m in args.candidate_models.split(",") if m.strip()]

    try:
        result = run_calibration(
            task_id=args.task_id,
            sample_size=args.sample_size,
            max_cost_usd=args.max_cost_usd,
            rubric_path=rubric_path,
            candidate_models=candidate_models,
            routing_path=args.routing_json,
            sample_source=args.sample_source,
            verifier=args.verifier,
            mock=args.mock,
            dry_run=args.dry_run,
        )
    except Exception as exc:  # pragma: no cover
        result = {
            "schema": SCHEMA,
            "task_id": args.task_id,
            "verdict": "error",
            "decision_rationale": f"calibrator exception: {exc!r}",
        }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[R65 calibrator] task={args.task_id} verdict={result.get('verdict')}")
        if "winner" in result:
            print(f"  winner:     {result['winner']}")
            print(f"  flash:      {result.get('flash_score')}")
            print(f"  pro:        {result.get('pro_score')}")
            print(f"  rationale:  {result.get('decision_rationale')}")
            print(f"  cost:       ${result.get('calibration_cost_usd'):.4f}")
            print(f"  evidence:   {result.get('evidence_dir')}")
        if result.get("verdict") == "error":
            print(f"  rationale:  {result.get('decision_rationale')}")

    if result.get("verdict") == "error":
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
