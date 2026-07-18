#!/usr/bin/env python3
"""meta1-ab-measurement-analyze.py - analyzer for the META-1 A/B
controlled re-measurement log produced by
``tools/meta1-ab-measurement-dispatch.py``.

Reads the JSONL log, joins each cohort-A record to its sibling cohort-B
record by ``trial_id``, looks up each pair's produced drafts (via
``expected_draft_id`` resolved against ``<workspace>/.auditooor/
meta1_ab_drafts/<expected_draft_id>.md`` by default, or a custom path
via ``--drafts-dir``), runs the load-bearing R-rule gates against each
draft, and reports per-rule fail-rate deltas between the two cohorts
with a Wilson-score binomial proportion confidence interval.

Honest constraint
-----------------

If neither cohort has a resolved draft yet (e.g. the measurement
window is still accumulating), the analyzer reports a structured
``insufficient_data`` verdict per-rule rather than emitting noise.

Usage
-----

::

    python3 tools/meta1-ab-measurement-analyze.py \\
        --log /Users/wolf/audits/dydx/.auditooor/meta1_ab_log.jsonl \\
        --drafts-dir /Users/wolf/audits/dydx/.auditooor/meta1_ab_drafts \\
        --confidence 0.95 \\
        --json

For the report-only "what's in the log so far" form (no drafts
required)::

    python3 tools/meta1-ab-measurement-analyze.py \\
        --log <path> \\
        --inventory

The inventory mode reports trial counts, matched-pair counts, and
META-1 invocation statuses observed without scoring any rules.

Schema (output JSON)
--------------------

::

    {
      "schema": "auditooor.meta1_ab_analyze_response.v1",
      "log_path": "<abs>",
      "trial_count": <int>,
      "matched_pair_count": <int>,
      "orphan_records": [<trial_id>: cohort],
      "meta1_status_breakdown": {"real": N, "fallback": N, "disabled": N},
      "per_rule_results": [
        {
          "rule_id": "R42",
          "cohort_a": {
            "n": <int>, "fails": <int>, "fail_rate": <float>
          },
          "cohort_b": {
            "n": <int>, "fails": <int>, "fail_rate": <float>
          },
          "delta_fail_rate": <float>,    # cohort_a - cohort_b
          "confidence_interval_95": [<low>, <high>],
          "verdict": "insufficient_data" | "helpful" | "inert" | "harmful",
          "notes": "<diagnostic>"
        },
        ...
      ],
      "overall_verdict": "insufficient_data" | "helpful" | "inert" | "harmful"
    }
"""
from __future__ import annotations

import argparse
import json
import math
import pathlib
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL_VERSION = "0.1.0"

# Rule-tool mapping. Each entry is (rule_id, tool path relative to repo,
# verdict-key in the tool's --json output that marks failure).
RULE_TOOLS = (
    ("R29", "tools/commitment-vs-validation-check.py"),
    ("R42", "tools/configured-impact-trace-check.py"),
    ("R43", "tools/load-bearing-bytes-attribution-check.py"),
    ("R45", "tools/designed-as-intended-precheck.py"),
    ("R46", "tools/trusted-infrastructure-compromise-check.py"),
    ("R52", "tools/rubric-row-coverage-check.py"),
)

# Verdict tokens we treat as "fail" for the per-rule fail-rate.
FAIL_VERDICT_PREFIXES = ("fail-",)
# Verdict tokens we treat as "skip / N/A" - excluded from rate denominator.
SKIP_VERDICT_PREFIXES = ("pass-out-of-scope", "pass-not-", "pass-no-")
# "ok-rebuttal" + "pass-*" (other than skip) are non-fail.


# ---------------------------------------------------------------------------
# Log loader
# ---------------------------------------------------------------------------

def load_log(log_path: pathlib.Path) -> List[Dict[str, Any]]:
    if not log_path.is_file():
        return []
    records: List[Dict[str, Any]] = []
    with log_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def group_by_trial(
    records: List[Dict[str, Any]],
) -> Tuple[Dict[str, Dict[str, Dict[str, Any]]], List[Tuple[str, str]]]:
    """Returns (groups, orphans) where groups[trial_id]["A"] = record
    and orphans is list of (trial_id, cohort) lacking a sibling."""
    groups: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for rec in records:
        trial = rec.get("trial_id", "")
        cohort = rec.get("cohort", "")
        if not trial or cohort not in ("A", "B"):
            continue
        groups.setdefault(trial, {})[cohort] = rec
    orphans: List[Tuple[str, str]] = []
    for trial, cohort_map in groups.items():
        if "A" not in cohort_map:
            orphans.append((trial, "missing-A"))
        if "B" not in cohort_map:
            orphans.append((trial, "missing-B"))
    return groups, orphans


# ---------------------------------------------------------------------------
# Draft resolution
# ---------------------------------------------------------------------------

def resolve_draft_path(
    record: Dict[str, Any],
    drafts_dir: Optional[pathlib.Path],
) -> Optional[pathlib.Path]:
    expected_id = record.get("expected_draft_id") or ""
    workspace = pathlib.Path(record.get("workspace_path", "")).expanduser()
    candidate_dirs: List[pathlib.Path] = []
    if drafts_dir is not None:
        candidate_dirs.append(drafts_dir)
    if workspace and workspace.is_dir():
        candidate_dirs.append(workspace / ".auditooor" / "meta1_ab_drafts")
    if not expected_id:
        return None
    for cand_dir in candidate_dirs:
        p_md = cand_dir / f"{expected_id}.md"
        if p_md.is_file():
            return p_md
        # Some operators may write .txt; check that too.
        p_txt = cand_dir / f"{expected_id}.txt"
        if p_txt.is_file():
            return p_txt
    return None


# ---------------------------------------------------------------------------
# Per-rule gate runner
# ---------------------------------------------------------------------------

def run_rule_check(
    rule_id: str,
    rule_tool_rel: str,
    draft_path: pathlib.Path,
    workspace: pathlib.Path,
    severity: str,
    runner: Optional[Any] = None,
) -> Dict[str, Any]:
    tool_path = REPO_ROOT / rule_tool_rel
    if not tool_path.is_file():
        return {
            "rule_id": rule_id,
            "verdict": "tool-missing",
            "raw": None,
            "error": f"tool not found: {tool_path}",
        }
    argv = [
        sys.executable,
        str(tool_path),
        str(draft_path),
        "--workspace",
        str(workspace),
        "--severity",
        severity.lower() if severity else "auto",
        "--json",
    ]
    if runner is None:
        try:
            proc = subprocess.run(  # noqa: S603,S607
                argv,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            return {
                "rule_id": rule_id,
                "verdict": "tool-timeout",
                "raw": None,
                "error": "timeout",
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "rule_id": rule_id,
                "verdict": "tool-error",
                "raw": None,
                "error": repr(exc),
            }
    else:
        proc = runner(argv)
    out = (proc.stdout or "").strip()
    verdict = None
    raw_obj = None
    if out:
        try:
            raw_obj = json.loads(out)
            verdict = raw_obj.get("verdict")
        except json.JSONDecodeError:
            # Try last JSON line.
            for line in reversed(out.splitlines()):
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        raw_obj = json.loads(line)
                        verdict = raw_obj.get("verdict")
                        break
                    except json.JSONDecodeError:
                        continue
    if verdict is None:
        return {
            "rule_id": rule_id,
            "verdict": "unparseable",
            "raw": raw_obj,
            "error": (proc.stderr or "")[:200],
        }
    return {
        "rule_id": rule_id,
        "verdict": verdict,
        "raw": raw_obj,
    }


def is_fail(verdict: str) -> bool:
    return any(verdict.startswith(p) for p in FAIL_VERDICT_PREFIXES)


def is_skip(verdict: str) -> bool:
    return any(verdict.startswith(p) for p in SKIP_VERDICT_PREFIXES)


# ---------------------------------------------------------------------------
# Wilson-score confidence interval
# ---------------------------------------------------------------------------

def wilson_score_interval(
    successes: int, n: int, z: float = 1.96
) -> Tuple[float, float]:
    """Two-sided Wilson-score CI for a binomial proportion. Returns
    (low, high). Handles n=0 by returning (0.0, 1.0)."""
    if n == 0:
        return (0.0, 1.0)
    p_hat = successes / n
    denom = 1.0 + (z * z) / n
    center = (p_hat + (z * z) / (2 * n)) / denom
    margin = (
        z
        * math.sqrt(
            (p_hat * (1.0 - p_hat) / n) + (z * z) / (4 * n * n)
        )
    ) / denom
    low = max(0.0, center - margin)
    high = min(1.0, center + margin)
    return (low, high)


def delta_ci(
    fails_a: int,
    n_a: int,
    fails_b: int,
    n_b: int,
    z: float = 1.96,
) -> Tuple[float, float]:
    """Approximate two-sided CI for (p_a - p_b) by treating them as
    independent binomials. Returns (low, high). Falls back to (-1, 1)
    when either n is zero."""
    if n_a == 0 or n_b == 0:
        return (-1.0, 1.0)
    p_a = fails_a / n_a
    p_b = fails_b / n_b
    se = math.sqrt(
        (p_a * (1.0 - p_a)) / n_a + (p_b * (1.0 - p_b)) / n_b
    )
    delta = p_a - p_b
    return (max(-1.0, delta - z * se), min(1.0, delta + z * se))


# ---------------------------------------------------------------------------
# Per-rule verdict classification
# ---------------------------------------------------------------------------

def classify_rule_result(
    n_a: int, fails_a: int, n_b: int, fails_b: int
) -> Tuple[str, str]:
    """Return (verdict, notes) for the rule. Verdict in
    insufficient_data | helpful | inert | harmful."""
    if n_a == 0 and n_b == 0:
        return (
            "insufficient_data",
            "Both cohorts have zero scoreable drafts for this rule.",
        )
    if n_a == 0 or n_b == 0:
        return (
            "insufficient_data",
            f"Cohort A n={n_a}; Cohort B n={n_b}; need >=1 in each.",
        )
    # Small-sample threshold: require >=6 per cohort before issuing a
    # non-insufficient verdict (Wilson CI gets very wide below this).
    if n_a < 6 or n_b < 6:
        return (
            "insufficient_data",
            f"Sample too small for binomial inference (A n={n_a}, B n={n_b}); "
            "need >=6 per cohort.",
        )
    low, high = delta_ci(fails_a, n_a, fails_b, n_b)
    # Helpful = META-1 cohort A has STRICTLY LOWER fail-rate than B
    # (delta < 0) AND CI excludes zero on the upper end.
    if high < 0.0:
        return (
            "helpful",
            f"Cohort A fail rate is lower than B; 95% CI of delta "
            f"({low:.3f}, {high:.3f}) excludes 0.",
        )
    if low > 0.0:
        return (
            "harmful",
            f"Cohort A fail rate is higher than B; 95% CI of delta "
            f"({low:.3f}, {high:.3f}) excludes 0.",
        )
    return (
        "inert",
        f"95% CI of delta ({low:.3f}, {high:.3f}) straddles 0; no signal.",
    )


# ---------------------------------------------------------------------------
# Analyzer entrypoint
# ---------------------------------------------------------------------------

def analyze(
    log_path: pathlib.Path,
    *,
    drafts_dir: Optional[pathlib.Path],
    rule_filter: Optional[List[str]] = None,
    rule_runner: Optional[Any] = None,
) -> Dict[str, Any]:
    records = load_log(log_path)
    groups, orphans = group_by_trial(records)
    meta1_status_breakdown: Dict[str, int] = {
        "real": 0,
        "fallback": 0,
        "disabled": 0,
    }
    for rec in records:
        status = rec.get("meta1_invocation_status", "")
        if status in meta1_status_breakdown:
            meta1_status_breakdown[status] += 1

    matched_pairs = [
        (trial, cohort_map["A"], cohort_map["B"])
        for trial, cohort_map in groups.items()
        if "A" in cohort_map and "B" in cohort_map
    ]

    # Per-rule fail-rate calc.
    rules = (
        [r for r in RULE_TOOLS if r[0] in rule_filter]
        if rule_filter
        else list(RULE_TOOLS)
    )
    per_rule_results: List[Dict[str, Any]] = []
    for rule_id, rule_tool_rel in rules:
        a_n = 0
        a_fail = 0
        b_n = 0
        b_fail = 0
        a_verdicts: List[str] = []
        b_verdicts: List[str] = []
        for _trial, rec_a, rec_b in matched_pairs:
            for rec, n_acc, fail_acc, vacc in (
                (rec_a, "a_n", "a_fail", a_verdicts),
                (rec_b, "b_n", "b_fail", b_verdicts),
            ):
                draft = resolve_draft_path(rec, drafts_dir)
                if draft is None:
                    continue
                workspace = pathlib.Path(rec.get("workspace_path", "")).expanduser()
                severity = rec.get("severity", "auto")
                result = run_rule_check(
                    rule_id,
                    rule_tool_rel,
                    draft,
                    workspace,
                    severity,
                    runner=rule_runner,
                )
                verdict = result.get("verdict", "unparseable")
                vacc.append(verdict)
                if verdict in (
                    "tool-missing",
                    "tool-timeout",
                    "tool-error",
                    "unparseable",
                ):
                    continue
                if is_skip(verdict):
                    continue
                if n_acc == "a_n":
                    a_n += 1
                    if is_fail(verdict):
                        a_fail += 1
                else:
                    b_n += 1
                    if is_fail(verdict):
                        b_fail += 1
        verdict, notes = classify_rule_result(a_n, a_fail, b_n, b_fail)
        per_rule_results.append(
            {
                "rule_id": rule_id,
                "cohort_a": {
                    "n": a_n,
                    "fails": a_fail,
                    "fail_rate": (a_fail / a_n) if a_n else None,
                    "verdicts": a_verdicts,
                },
                "cohort_b": {
                    "n": b_n,
                    "fails": b_fail,
                    "fail_rate": (b_fail / b_n) if b_n else None,
                    "verdicts": b_verdicts,
                },
                "delta_fail_rate": (
                    (a_fail / a_n) - (b_fail / b_n)
                    if a_n and b_n
                    else None
                ),
                "confidence_interval_95": list(
                    delta_ci(a_fail, a_n, b_fail, b_n)
                ),
                "verdict": verdict,
                "notes": notes,
            }
        )

    # Overall verdict (aggregate).
    rule_verdicts = [r["verdict"] for r in per_rule_results]
    if all(v == "insufficient_data" for v in rule_verdicts):
        overall = "insufficient_data"
    elif any(v == "harmful" for v in rule_verdicts):
        overall = "harmful"
    elif any(v == "helpful" for v in rule_verdicts) and not any(
        v == "harmful" for v in rule_verdicts
    ):
        overall = "helpful"
    else:
        overall = "inert"

    return {
        "schema": "auditooor.meta1_ab_analyze_response.v1",
        "tool_version": TOOL_VERSION,
        "log_path": str(log_path),
        "trial_count": len(groups),
        "matched_pair_count": len(matched_pairs),
        "orphan_records": [
            {"trial_id": t, "missing": m} for t, m in orphans
        ],
        "meta1_status_breakdown": meta1_status_breakdown,
        "per_rule_results": per_rule_results,
        "overall_verdict": overall,
    }


def inventory(log_path: pathlib.Path) -> Dict[str, Any]:
    records = load_log(log_path)
    groups, orphans = group_by_trial(records)
    matched_pair_count = sum(
        1 for cm in groups.values() if "A" in cm and "B" in cm
    )
    # Aggregate meta1 status across ALL records (legacy).
    meta1_status: Dict[str, int] = {
        "real": 0,
        "fallback": 0,
        "disabled": 0,
    }
    # Separate cohort-A breakdown: cohort B is always "disabled by
    # design" (we never invoke the wrapper for B); cohort A is where
    # the real / fallback / wrapper-error distinction matters.
    cohort_a_status: Dict[str, int] = {
        "real": 0,
        "fallback": 0,
        "disabled": 0,
    }
    lane_type_counts: Dict[str, int] = {}
    severity_counts: Dict[str, int] = {}
    for rec in records:
        status = rec.get("meta1_invocation_status", "")
        if status in meta1_status:
            meta1_status[status] += 1
        if rec.get("cohort") == "A" and status in cohort_a_status:
            cohort_a_status[status] += 1
        lt = rec.get("lane_type", "")
        if lt:
            lane_type_counts[lt] = lane_type_counts.get(lt, 0) + 1
        sev = rec.get("severity", "")
        if sev:
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
    return {
        "schema": "auditooor.meta1_ab_inventory_response.v1",
        "tool_version": TOOL_VERSION,
        "log_path": str(log_path),
        "record_count": len(records),
        "trial_count": len(groups),
        "matched_pair_count": matched_pair_count,
        "orphan_count": len(orphans),
        "orphans": [{"trial_id": t, "missing": m} for t, m in orphans],
        "meta1_status_breakdown": meta1_status,
        "cohort_a_status_breakdown": cohort_a_status,
        "lane_type_breakdown": lane_type_counts,
        "severity_breakdown": severity_counts,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="meta1-ab-measurement-analyze.py",
        description=__doc__.splitlines()[0] if __doc__ else "",
    )
    p.add_argument(
        "--log",
        required=True,
        help="Path to the JSONL log written by meta1-ab-measurement-dispatch.py.",
    )
    p.add_argument(
        "--drafts-dir",
        default=None,
        help=(
            "Directory holding produced drafts (named <expected_draft_id>.md). "
            "Defaults to <workspace>/.auditooor/meta1_ab_drafts/ per record."
        ),
    )
    p.add_argument(
        "--rule",
        action="append",
        default=None,
        help="Restrict to specific rule(s) (R29, R42, ...). Repeatable.",
    )
    p.add_argument(
        "--inventory",
        action="store_true",
        help="Report log inventory only (no rule scoring).",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON to stdout (default).",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    log_path = pathlib.Path(args.log).expanduser().resolve()
    drafts_dir = (
        pathlib.Path(args.drafts_dir).expanduser().resolve()
        if args.drafts_dir
        else None
    )
    if args.inventory:
        out = inventory(log_path)
    else:
        out = analyze(
            log_path,
            drafts_dir=drafts_dir,
            rule_filter=args.rule,
        )
    print(json.dumps(out, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
