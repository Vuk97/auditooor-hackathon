#!/usr/bin/env python3
"""Outcome-calibrated routing feedback tool (Lane 10, KLBQ priority-8).

Closes the loop that exploit-conversion-benchmark.py measures but does not
feed back into. Reads the benchmark report (and optionally submission outcome
data), computes outcome signals, and emits ADVISORY routing/scoring
recommendations.

ADVISORY ONLY - this tool NEVER mutates any live config file, exploit-queue
ranking weights, llm_budget_log, or source-mining-campaign routing thresholds.
It only writes one output file: reports/outcome_calibrated_routing.json.
The operator or a downstream wired step applies the recommendations.

Signal computation:
  filing_rate           = rows_filed / queue_rows_generated  (ideally >= 0.15)
  proved_vs_killed      = rows_proved / (rows_proved + rows_killed) or None
  dupe_rate             = rows_duplicate / rows_filed  (if filed > 0)
  oos_rate              = rows_oos / rows_filed  (if filed > 0)
  inconclusive_rate     = rows_inconclusive / queue_rows_generated
  proof_gap             = 1.0 - rows_with_runnable_proof_path / queue_rows_generated
  attacker_control_gap  = 1.0 - rows_with_plausible_attacker_control / queue_rows_generated
  tokens_per_verdict    = provider_tokens_per_useful_verdict (raw from benchmark)

Thresholds used to trigger recommendations:
  filing_rate < LOW_FILING_RATE_THRESHOLD (0.10) -> tighten proof-shell bar
  dupe_rate   > HIGH_DUPE_RATE_THRESHOLD  (0.30) -> down-weight high-dupe attack classes
  oos_rate    > HIGH_OOS_RATE_THRESHOLD   (0.25) -> raise scope-check gate
  inconclusive_rate > HIGH_INCONCLUSIVE_THRESHOLD (0.70) -> require truth-table completion earlier
  proof_gap   > HIGH_PROOF_GAP_THRESHOLD  (0.80) -> add proof-shell generation step
  attacker_control_gap > HIGH_CTRL_GAP    (0.60) -> require attacker_control != missing before enqueue

Schema: auditooor.outcome_calibrated_routing.v1

CLI:
    python3 tools/outcome-calibrated-routing.py \\
        [--workspace <ws>] [--benchmark-json <path>] \\
        [--output <path>] [--json]

Exit codes:
    0  recommendations emitted (even when all signals are healthy - emits empty list)
    1  fatal error (unrecoverable)
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.outcome_calibrated_routing.v1"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BENCHMARK_JSON = REPO_ROOT / "reports" / "exploit_conversion_benchmark.json"
DEFAULT_OUTPUT = REPO_ROOT / "reports" / "outcome_calibrated_routing.json"

# ---------------------------------------------------------------------------
# Thresholds (advisory - adjust via env or caller; these are sensible defaults)
# ---------------------------------------------------------------------------
LOW_FILING_RATE_THRESHOLD   = 0.10   # below -> tighten proof bar
TARGET_FILING_RATE          = 0.15   # used in recommendation text
HIGH_DUPE_RATE_THRESHOLD    = 0.30   # above -> down-weight high-dupe classes
HIGH_OOS_RATE_THRESHOLD     = 0.25   # above -> raise scope-check gate
HIGH_INCONCLUSIVE_THRESHOLD = 0.70   # above -> require truth-table earlier
HIGH_PROOF_GAP_THRESHOLD    = 0.80   # above -> add proof-shell step
HIGH_CTRL_GAP_THRESHOLD     = 0.60   # above -> gate enqueue on attacker_control


# ---------------------------------------------------------------------------
# Signal computation
# ---------------------------------------------------------------------------

def _safe_rate(numerator: float | int, denominator: float | int,
               default: float | None = None) -> float | None:
    """Return numerator/denominator, guarding zero division."""
    if not denominator:
        return default
    return round(numerator / denominator, 4)


def compute_signals(ws_row: dict[str, Any]) -> dict[str, Any]:
    """Compute normalised outcome signals from a single workspace benchmark row."""
    q = ws_row.get("queue_rows_generated", 0)
    proved     = ws_row.get("rows_proved", 0)
    killed     = ws_row.get("rows_killed", 0)
    inconc     = ws_row.get("rows_inconclusive", 0)
    filed      = ws_row.get("rows_filed", 0)
    dupes      = ws_row.get("rows_duplicate", 0)
    oos        = ws_row.get("rows_oos", 0)
    runnable   = ws_row.get("rows_with_runnable_proof_path", 0)
    ctrl       = ws_row.get("rows_with_plausible_attacker_control", 0)
    tpuv       = ws_row.get("provider_tokens_per_useful_verdict")

    filing_rate          = _safe_rate(filed, q)
    proved_vs_killed     = _safe_rate(proved, proved + killed)
    dupe_rate            = _safe_rate(dupes, filed)
    oos_rate             = _safe_rate(oos, filed)
    inconclusive_rate    = _safe_rate(inconc, q)
    proof_gap            = _safe_rate(q - runnable, q)
    attacker_control_gap = _safe_rate(q - ctrl, q)

    return {
        "queue_rows":             q,
        "filing_rate":            filing_rate,
        "proved_vs_killed_ratio": proved_vs_killed,
        "dupe_rate":              dupe_rate,
        "oos_rate":               oos_rate,
        "inconclusive_rate":      inconclusive_rate,
        "proof_gap":              proof_gap,
        "attacker_control_gap":   attacker_control_gap,
        "tokens_per_useful_verdict": tpuv,
    }


# ---------------------------------------------------------------------------
# Recommendation generation
# ---------------------------------------------------------------------------

def _recommend(signals: dict[str, Any], workspace: str) -> list[dict[str, Any]]:
    """Return a list of advisory recommendation dicts for one workspace."""
    recs: list[dict[str, Any]] = []

    filing_rate       = signals.get("filing_rate")
    dupe_rate         = signals.get("dupe_rate")
    oos_rate          = signals.get("oos_rate")
    inconc_rate       = signals.get("inconclusive_rate")
    proof_gap         = signals.get("proof_gap")
    ctrl_gap          = signals.get("attacker_control_gap")
    tpuv              = signals.get("tokens_per_useful_verdict")
    q                 = signals.get("queue_rows", 0)

    # -- 1. Low filing rate: tighten proof-shell required bar ---------------
    if filing_rate is not None and filing_rate < LOW_FILING_RATE_THRESHOLD:
        recs.append({
            "recommendation_id": "raise-proof-shell-bar",
            "priority":          "high",
            "workspace":         workspace,
            "signal":            "filing_rate",
            "observed_value":    filing_rate,
            "threshold":         LOW_FILING_RATE_THRESHOLD,
            "direction":         "below",
            "action":            "raise-proof-shell-required-bar",
            "description": (
                f"Filing rate {filing_rate:.0%} is below the {LOW_FILING_RATE_THRESHOLD:.0%} floor. "
                f"Require a runnable proof shell (foundry/cosmos-production) before a row enters "
                f"the exploit queue. Rows with proof_path=missing should not be enqueued; "
                f"they should be routed to the proof-shell-generator step first. "
                f"Target: filing_rate >= {TARGET_FILING_RATE:.0%}."
            ),
            "affected_dimension":  "exploit-queue-enqueue-gate",
            "suggested_config_key": "require_runnable_proof_path_before_enqueue",
            "suggested_value":      True,
            "advisory_only":        True,
        })

    # -- 2. High dupe rate: down-weight high-dupe attack classes ------------
    if dupe_rate is not None and dupe_rate > HIGH_DUPE_RATE_THRESHOLD:
        recs.append({
            "recommendation_id": "down-weight-dupe-classes",
            "priority":          "high",
            "workspace":         workspace,
            "signal":            "dupe_rate",
            "observed_value":    dupe_rate,
            "threshold":         HIGH_DUPE_RATE_THRESHOLD,
            "direction":         "above",
            "action":            "down-weight-high-dupe-attack-classes",
            "description": (
                f"Dupe rate {dupe_rate:.0%} of filed reports exceeds {HIGH_DUPE_RATE_THRESHOLD:.0%}. "
                f"Reduce the _DUPE_RISK_SCORE weight contribution in exploit-queue ranking "
                f"(currently 0.10 of priority_score), or add a pre-enqueue dupe-preflight "
                f"check that calls duplicate-preflight-check.py before a candidate row is "
                f"promoted. High-dupe attack classes should receive a lower routing priority "
                f"until the dupe-check gate is wired."
            ),
            "affected_dimension":  "dupe_risk_score-weight",
            "suggested_config_key": "dupe_risk_score_weight",
            "suggested_value":      0.05,  # halved from 0.10
            "advisory_only":        True,
        })

    # -- 3. High OOS rate: raise scope-check gate ---------------------------
    if oos_rate is not None and oos_rate > HIGH_OOS_RATE_THRESHOLD:
        recs.append({
            "recommendation_id": "raise-scope-check-gate",
            "priority":          "medium",
            "workspace":         workspace,
            "signal":            "oos_rate",
            "observed_value":    oos_rate,
            "threshold":         HIGH_OOS_RATE_THRESHOLD,
            "direction":         "above",
            "action":            "add-scope-check-before-enqueue",
            "description": (
                f"OOS rejection rate {oos_rate:.0%} of filed reports exceeds "
                f"{HIGH_OOS_RATE_THRESHOLD:.0%}. Run per-finding-oos-check.py "
                f"(or pre-submit-check.sh OOS gates) before the candidate is routed "
                f"to a proof-building worker. Candidates that fail OOS check should "
                f"be diverted to the held queue, not the filing queue."
            ),
            "affected_dimension":  "pre-enqueue-oos-gate",
            "suggested_config_key": "require_scope_check_before_proof_build",
            "suggested_value":      True,
            "advisory_only":        True,
        })

    # -- 4. High inconclusive rate: require truth-table completion earlier ---
    if inconc_rate is not None and inconc_rate > HIGH_INCONCLUSIVE_THRESHOLD and q > 0:
        recs.append({
            "recommendation_id": "require-truth-table-early",
            "priority":          "medium",
            "workspace":         workspace,
            "signal":            "inconclusive_rate",
            "observed_value":    inconc_rate,
            "threshold":         HIGH_INCONCLUSIVE_THRESHOLD,
            "direction":         "above",
            "action":            "gate-proof-routing-on-truth-table-complete",
            "description": (
                f"Inconclusive rate {inconc_rate:.0%} of queue rows exceeds "
                f"{HIGH_INCONCLUSIVE_THRESHOLD:.0%}. Rows should not be dispatched "
                f"to a proof-building worker until their truth-table (attacker_control, "
                f"impact_path, proof_path, quality_gate_status) is complete. "
                f"Add a truth-table completeness gate at the dispatch step "
                f"(LEARNING_ROUTES_PROOF already requires this; enforce at the queue level too)."
            ),
            "affected_dimension":  "truth-table-completeness-gate",
            "suggested_config_key": "gate_dispatch_on_truth_table_complete",
            "suggested_value":      True,
            "advisory_only":        True,
        })

    # -- 5. High proof gap: add proof-shell generation step -----------------
    if proof_gap is not None and proof_gap > HIGH_PROOF_GAP_THRESHOLD and q > 0:
        recs.append({
            "recommendation_id": "add-proof-shell-generator-step",
            "priority":          "medium",
            "workspace":         workspace,
            "signal":            "proof_gap",
            "observed_value":    proof_gap,
            "threshold":         HIGH_PROOF_GAP_THRESHOLD,
            "direction":         "above",
            "action":            "route-missing-proof-rows-to-shell-generator",
            "description": (
                f"Proof gap {proof_gap:.0%} of queue rows lack a runnable proof path. "
                f"Route these rows through harness-scaffold (or invariant-harness-generator.py) "
                f"before they compete for proof-building worker capacity. "
                f"This prevents workers from receiving under-specified rows where the "
                f"proof_path=missing and spending tokens with low filing-rate return."
            ),
            "affected_dimension":  "proof-path-required-routing",
            "suggested_config_key": "auto_route_missing_proof_to_shell_generator",
            "suggested_value":      True,
            "advisory_only":        True,
        })

    # -- 6. High attacker control gap: gate enqueue on attacker_control -----
    if ctrl_gap is not None and ctrl_gap > HIGH_CTRL_GAP_THRESHOLD and q > 0:
        recs.append({
            "recommendation_id": "gate-enqueue-on-attacker-control",
            "priority":          "low",
            "workspace":         workspace,
            "signal":            "attacker_control_gap",
            "observed_value":    ctrl_gap,
            "threshold":         HIGH_CTRL_GAP_THRESHOLD,
            "direction":         "above",
            "action":            "require-attacker-control-confirmed-before-proof-dispatch",
            "description": (
                f"Attacker control gap {ctrl_gap:.0%} of queue rows have attacker_control=missing. "
                f"Require attacker_control != missing before a row is dispatched to a "
                f"proof-building worker. Rows with missing control should be routed to "
                f"a source-read lane first to establish whether control is partial/known."
            ),
            "affected_dimension":  "attacker-control-dispatch-gate",
            "suggested_config_key": "require_attacker_control_before_proof_dispatch",
            "suggested_value":      "partial-or-known",
            "advisory_only":        True,
        })

    # -- 7. Token efficiency: high spend per verdict -----------------------
    if tpuv is not None and q > 0:
        # Flag if >5M tokens per useful verdict (rough heuristic)
        if tpuv > 5_000_000:
            recs.append({
                "recommendation_id": "reduce-token-burn-per-verdict",
                "priority":          "low",
                "workspace":         workspace,
                "signal":            "tokens_per_useful_verdict",
                "observed_value":    tpuv,
                "threshold":         5_000_000,
                "direction":         "above",
                "action":            "route-low-confidence-rows-to-cheaper-provider",
                "description": (
                    f"Token cost per useful verdict is {tpuv:,.0f} - above the 5M advisory ceiling. "
                    f"Consider routing low-confidence (severity_confidence=low) rows to a "
                    f"cheaper provider tier first. Reserve high-context providers for rows "
                    f"where proof_path is runnable and attacker_control is known/partial."
                ),
                "affected_dimension":  "provider-routing-by-confidence",
                "suggested_config_key": "route_low_confidence_to_cheap_provider",
                "suggested_value":      True,
                "advisory_only":        True,
            })

    return recs


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def build_routing_report(
    benchmark_path: Path,
    workspace_filter: str | None = None,
) -> dict[str, Any]:
    """Read the benchmark JSON and emit advisory routing recommendations."""

    generated_at = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Load benchmark
    benchmark_data: dict[str, Any] = {}
    benchmark_loaded = False
    benchmark_error: str | None = None

    if benchmark_path.exists():
        try:
            benchmark_data = json.loads(benchmark_path.read_text(encoding="utf-8"))
            benchmark_loaded = True
        except Exception as exc:
            benchmark_error = str(exc)
    else:
        benchmark_error = f"benchmark file not found: {benchmark_path}"

    # Validate schema (advisory - do not crash on mismatch)
    if benchmark_loaded:
        found_schema = benchmark_data.get("schema", "")
        if not found_schema.startswith("auditooor.exploit_conversion_benchmark"):
            benchmark_error = (
                f"unexpected benchmark schema '{found_schema}'; "
                "expected auditooor.exploit_conversion_benchmark.v1"
            )
            benchmark_loaded = False

    all_signals: list[dict[str, Any]] = []
    all_recommendations: list[dict[str, Any]] = []

    if benchmark_loaded:
        ws_rows: list[dict[str, Any]] = benchmark_data.get("workspaces", [])
        for ws_row in ws_rows:
            ws_name = ws_row.get("workspace", "unknown")
            if workspace_filter and ws_name != workspace_filter:
                # Also accept path-based match
                ws_path = ws_row.get("workspace_path", "")
                if workspace_filter not in ws_path:
                    continue
            signals = compute_signals(ws_row)
            signals["workspace"] = ws_name
            all_signals.append(signals)
            recs = _recommend(signals, ws_name)
            all_recommendations.extend(recs)

    # Healthy signal when no recommendations triggered
    status = "healthy" if (benchmark_loaded and not all_recommendations) else (
        "recommendations-emitted" if all_recommendations else "no-data"
    )

    report: dict[str, Any] = {
        "schema":           SCHEMA,
        "generated_at_utc": generated_at,
        "advisory_only":    True,
        "mutation_guard":   (
            "This tool NEVER writes to exploit-queue.py weights, "
            "llm_budget_log, source-mining-campaign routing, or any live config. "
            "All fields are advisory; apply via operator decision or a downstream wired step."
        ),
        "benchmark_source": str(benchmark_path),
        "benchmark_loaded": benchmark_loaded,
        "benchmark_error":  benchmark_error,
        "workspace_filter": workspace_filter,
        "status":           status,
        "thresholds_used": {
            "low_filing_rate":          LOW_FILING_RATE_THRESHOLD,
            "high_dupe_rate":           HIGH_DUPE_RATE_THRESHOLD,
            "high_oos_rate":            HIGH_OOS_RATE_THRESHOLD,
            "high_inconclusive_rate":   HIGH_INCONCLUSIVE_THRESHOLD,
            "high_proof_gap":           HIGH_PROOF_GAP_THRESHOLD,
            "high_attacker_control_gap": HIGH_CTRL_GAP_THRESHOLD,
        },
        "workspace_signals":     all_signals,
        "recommendations":       all_recommendations,
        "recommendation_count":  len(all_recommendations),
        "recommendation_ids":    [r["recommendation_id"] for r in all_recommendations],
    }

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Outcome-calibrated routing feedback tool (advisory only). "
            "Reads exploit-conversion-benchmark.json and emits routing recommendations."
        )
    )
    p.add_argument(
        "--workspace", metavar="PATH",
        help=(
            "Filter to a single workspace by name or path fragment. "
            "If omitted, all workspaces in the benchmark are processed."
        ),
    )
    p.add_argument(
        "--benchmark-json", metavar="PATH",
        default=str(DEFAULT_BENCHMARK_JSON),
        help=f"Path to exploit_conversion_benchmark.json (default: {DEFAULT_BENCHMARK_JSON})",
    )
    p.add_argument(
        "--output", metavar="PATH",
        default=str(DEFAULT_OUTPUT),
        help=f"Output JSON path (default: {DEFAULT_OUTPUT})",
    )
    p.add_argument(
        "--json", action="store_true",
        help="Also print JSON to stdout.",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    workspace_filter: str | None = None
    if args.workspace:
        # Accept either a bare name or a path; extract trailing component as filter hint
        ws_path = Path(args.workspace)
        workspace_filter = ws_path.name if ws_path.name else args.workspace

    benchmark_path = Path(args.benchmark_json)
    report = build_routing_report(benchmark_path, workspace_filter)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))

    n_recs = report["recommendation_count"]
    status  = report["status"]
    print(
        f"[outcome-calibrated-routing] status={status}; "
        f"{n_recs} recommendation(s) emitted; wrote {out_path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
