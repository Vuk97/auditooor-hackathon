#!/usr/bin/env python3
"""Pre-PoC lesson gate - candidate-aware evaluation before harness/proof work.

J5b remaining work: apply the shared outcome-lesson classifier to each
High/Critical exploit-queue candidate as a STRUCTURED OBJECT (parse candidate
fields individually, not by scanning raw queue JSON text). The gate is callable
in two contexts:

  (a) before prove-top-leads  - block harness-binding on hard lesson predicates
  (b) inside exploit-conversion-loop - over each conversion candidate row

Waivers are typed (owner + reason + expiry) and stored in the workspace
`.auditooor/pre_poc_lesson_gate_waivers.json` file so they survive across runs.

This tool CALLS outcome-lesson-gate.py as a library (imported) but performs its
own per-candidate structuring pass - the key J5b delta vs. the existing
prove-top-leads gate which scanned only the raw queue JSON blob.

Output schema: auditooor.pre_poc_lesson_gate.v1
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.pre_poc_lesson_gate.v1"
SCHEMA_VERSION = "1.0"
TOOL_VERSION = "1.0.0"

# Severities treated as High or Critical (case-insensitive match)
HIGH_CRITICAL_RE = re.compile(r"\b(high|critical|crit)\b", re.IGNORECASE)

# Queue container key search order (mirrors outcome-lesson-gate.py)
QUEUE_CONTAINER_KEYS = ("queue", "candidates", "candidate_rows", "leads", "rows", "items")

# Fields we extract from each candidate row for structured evaluation.
# These map to the CANDIDATE_FIELDS understood by outcome-lesson-gate._match_candidate_record.
CANDIDATE_FIELDS = (
    "attacker_role",
    "prerequisites",
    "impact_claim",
    "evidence_class",
    "production_path",
    "economics",
    "oos_flags",
    # extras used for severity filtering and identity
    "likely_severity",
    "severity",
    "lead_id",
    "candidate_id",
    "id",
    "title",
    "attack_class",
    "victim_role",
    "impact_path",
    "asset_at_risk",
    "blockers",
    # exploit-queue specific extras
    "production_path_requirement",
    "attacker_control",
    "root_cause_hypothesis",
    "truth_table_summary",
    "likely_triager_objection",
)


# ---------------------------------------------------------------------------
# Waiver helpers
# ---------------------------------------------------------------------------

WAIVERS_FILENAME = "pre_poc_lesson_gate_waivers.json"


def _load_waivers(auditooor_dir: Path) -> dict[str, Any]:
    """Load typed waivers from workspace. Returns empty dict on any error."""
    path = auditooor_dir / WAIVERS_FILENAME
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return raw
    except Exception:  # noqa: BLE001
        pass
    return {}


def _save_waivers(auditooor_dir: Path, waivers: dict[str, Any]) -> None:
    auditooor_dir.mkdir(parents=True, exist_ok=True)
    path = auditooor_dir / WAIVERS_FILENAME
    path.write_text(json.dumps(waivers, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _waiver_key(candidate_id: str, predicate: str) -> str:
    return f"{candidate_id}::{predicate}"


def _is_waiver_valid(waiver: dict[str, Any]) -> bool:
    """Check typed waiver has required fields and has not expired."""
    if not isinstance(waiver, dict):
        return False
    if not waiver.get("owner") or not waiver.get("reason"):
        return False
    expiry = waiver.get("expiry_utc")
    if expiry:
        try:
            exp_dt = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))
            if exp_dt < datetime.now(timezone.utc):
                return False
        except (ValueError, TypeError):
            return False
    return True


# ---------------------------------------------------------------------------
# Outcome-lesson-gate loader
# ---------------------------------------------------------------------------

_GATE_MODULE: Any = None


def _load_gate() -> Any:
    global _GATE_MODULE
    if _GATE_MODULE is not None:
        return _GATE_MODULE
    gate_path = Path(__file__).resolve().with_name("outcome-lesson-gate.py")
    try:
        spec = importlib.util.spec_from_file_location("outcome_lesson_gate_for_pre_poc", gate_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load outcome-lesson-gate from {gate_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        _GATE_MODULE = module
        return module
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"Failed to import outcome-lesson-gate.py: {exc}") from exc


def _gate_active_levels(gate: Any, inventory_path: Path | None) -> tuple[dict[str, str], dict[str, Any]]:
    """Load active predicate levels from inventory or compiler catalog."""
    compiler = gate._load_compiler()
    active, meta, _warnings = gate.load_inventory(inventory_path, compiler)
    return active, meta


# ---------------------------------------------------------------------------
# Exploit-queue loading
# ---------------------------------------------------------------------------

def _candidate_id(row: dict[str, Any]) -> str:
    return str(
        row.get("lead_id")
        or row.get("candidate_id")
        or row.get("id")
        or row.get("title")
        or "unknown"
    )


def _candidate_severity(row: dict[str, Any]) -> str:
    return str(row.get("likely_severity") or row.get("severity") or "unknown").lower()


def _is_high_critical(row: dict[str, Any]) -> bool:
    sev = _candidate_severity(row)
    return bool(HIGH_CRITICAL_RE.search(sev))


def _find_exploit_queue(auditooor_dir: Path) -> Path | None:
    """Return the best available exploit-queue path."""
    for name in ("exploit_queue.source_mined.json", "exploit_queue.json"):
        p = auditooor_dir / name
        if p.is_file():
            return p
    return None


def _load_rows(queue_path: Path) -> tuple[list[dict[str, Any]], str]:
    """Load candidate rows from exploit queue. Returns (rows, error_msg)."""
    try:
        raw = json.loads(queue_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [], f"queue JSON load failed: {exc}"

    if not isinstance(raw, dict):
        return [], f"expected top-level object, got {type(raw).__name__}"

    for key in QUEUE_CONTAINER_KEYS:
        rows = raw.get(key)
        if isinstance(rows, list):
            return [r for r in rows if isinstance(r, dict)], ""

    # Fallback: check if top-level IS a candidate row (shouldn't happen, but be defensive)
    return [], "no candidate container key found; expected one of: " + ", ".join(QUEUE_CONTAINER_KEYS)


# ---------------------------------------------------------------------------
# Per-candidate structured evaluation
# ---------------------------------------------------------------------------

def _build_candidate_record(row: dict[str, Any], queue_path: Path, idx: int) -> dict[str, Any]:
    """Build a candidate record in the shape outcome-lesson-gate expects."""
    cid = _candidate_id(row)
    source_ref = f"{queue_path}#{cid}"

    # Extract only the fields the gate classifier understands
    candidate: dict[str, Any] = {}
    for field in CANDIDATE_FIELDS:
        if field in row:
            candidate[field] = row[field]

    # Map exploit-queue-specific fields to gate CANDIDATE_FIELDS when missing
    if "impact_claim" not in candidate and "impact_path" in row:
        candidate["impact_claim"] = row["impact_path"]
    if "production_path" not in candidate and "production_path_requirement" in row:
        candidate["production_path"] = row["production_path_requirement"]
    if "oos_flags" not in candidate and "asset_at_risk" in row:
        candidate["oos_flags"] = row["asset_at_risk"]
    if "prerequisites" not in candidate and "attacker_control" in row:
        candidate["prerequisites"] = row["attacker_control"]

    return {
        "source_ref": source_ref,
        "candidate": candidate,
        "field_presence": {field: field in candidate for field in (
            "attacker_role", "prerequisites", "impact_claim",
            "evidence_class", "production_path", "economics", "oos_flags"
        )},
    }


def evaluate_candidate(
    row: dict[str, Any],
    *,
    gate: Any,
    active_levels: dict[str, str],
    waivers: dict[str, Any],
    queue_path: Path,
    idx: int,
) -> dict[str, Any]:
    """Evaluate a single candidate row as a structured object. Returns a verdict dict."""
    cid = _candidate_id(row)
    severity = _candidate_severity(row)

    record = _build_candidate_record(row, queue_path, idx)

    # Run the gate's per-candidate matcher directly (structured, not text-scan)
    gate_compiler = gate._load_compiler()
    matched_rows, _suppressed = gate._match_candidate_record(gate_compiler, record, active_levels)

    hard_blockers = [r for r in matched_rows if not r.get("advisory_only")]
    advisory_hits = [r for r in matched_rows if r.get("advisory_only")]

    # Check waivers for each hard blocker
    effective_blockers = []
    waived_predicates: list[dict[str, Any]] = []
    for r in hard_blockers:
        pred = r["predicate"]
        wkey = _waiver_key(cid, pred)
        waiver = waivers.get(wkey)
        if _is_waiver_valid(waiver):
            waived_predicates.append({
                "predicate": pred,
                "waiver_owner": waiver.get("owner"),
                "waiver_reason": waiver.get("reason"),
                "waiver_expiry_utc": waiver.get("expiry_utc"),
            })
        else:
            effective_blockers.append(r)

    if effective_blockers:
        verdict = f"blocked_{effective_blockers[0]['predicate']}"
        status = "blocked"
    elif waived_predicates and not advisory_hits:
        verdict = "waived"
        status = "waived"
    elif waived_predicates:
        verdict = "waived"
        status = "waived"
    else:
        verdict = "pass"
        status = "pass"

    return {
        "candidate_id": cid,
        "title": str(row.get("title") or ""),
        "likely_severity": severity,
        "verdict": verdict,
        "status": status,
        "hard_blockers": [
            {
                "predicate": r["predicate"],
                "enforcement_level": r["enforcement_level"],
                "gate_phase": r.get("gate_phase"),
                "matched_signals": r.get("matched_signals", []),
                "candidate_fields": r.get("candidate_fields", []),
                "suggested_proof_obligations": r.get("suggested_proof_obligations", []),
            }
            for r in effective_blockers
        ],
        "advisory_warnings": [
            {
                "predicate": r["predicate"],
                "matched_signals": r.get("matched_signals", []),
            }
            for r in advisory_hits
        ],
        "waivers_applied": waived_predicates,
    }


# ---------------------------------------------------------------------------
# Main gate runner
# ---------------------------------------------------------------------------

def run_gate(
    workspace: Path,
    *,
    top_n: int = 10,
    context: str = "prove-top-leads",
    strict: bool = False,
    all_severities: bool = False,
    inventory_path: Path | None = None,
) -> dict[str, Any]:
    """Run the pre-PoC lesson gate over top-N High/Critical candidates.

    Args:
        workspace: Path to the audit workspace directory.
        top_n: Maximum number of top candidates to evaluate.
        context: Calling context tag ('prove-top-leads' or 'exploit-conversion-loop').
        strict: If True, exit-non-zero on any hard-blocked candidate with no valid waiver.
        all_severities: If True, evaluate all severities, not just High/Critical.
        inventory_path: Path to lesson-enforcement-inventory.json (optional).

    Returns a dict with schema auditooor.pre_poc_lesson_gate.v1.
    """
    auditooor_dir = workspace / ".auditooor"

    # Resolve inventory
    if inventory_path is None:
        ws_inv = auditooor_dir / "lesson_enforcement_inventory.json"
        repo_inv = ROOT / ".auditooor" / "lesson_enforcement_inventory.json"
        if ws_inv.is_file():
            inventory_path = ws_inv
        elif repo_inv.is_file():
            inventory_path = repo_inv

    # Find exploit queue
    queue_path = _find_exploit_queue(auditooor_dir)

    result: dict[str, Any] = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workspace": str(workspace),
        "context": context,
        "top_n": top_n,
        "strict": strict,
        "all_severities": all_severities,
        "offline_only": True,
        "network_access": False,
        "policy": (
            "This gate evaluates each candidate as a structured object. "
            "It never marks a candidate submission-ready. "
            "Hard blockers indicate required proof obligations before harness work."
        ),
        "promotion_authority": False,
        "submission_ready_claim": False,
    }

    # Missing artifact case
    if queue_path is None:
        result["status"] = "missing_artifact"
        result["verdict"] = "missing_artifact"
        result["candidate_rows"] = []
        result["summary"] = {
            "total_candidates": 0,
            "high_critical_candidates": 0,
            "evaluated": 0,
            "pass_count": 0,
            "blocked_count": 0,
            "waived_count": 0,
            "advisory_count": 0,
            "hard_blocked_predicate_counts": {},
        }
        result["warnings"] = [
            "no exploit queue found; checked exploit_queue.source_mined.json and exploit_queue.json"
        ]
        return result

    rows, load_err = _load_rows(queue_path)
    if load_err:
        result["status"] = "missing_artifact"
        result["verdict"] = "missing_artifact"
        result["queue_path"] = str(queue_path)
        result["candidate_rows"] = []
        result["summary"] = {
            "total_candidates": 0,
            "high_critical_candidates": 0,
            "evaluated": 0,
            "pass_count": 0,
            "blocked_count": 0,
            "waived_count": 0,
            "advisory_count": 0,
            "hard_blocked_predicate_counts": {},
        }
        result["warnings"] = [f"queue load error: {load_err}"]
        return result

    result["queue_path"] = str(queue_path)

    # Filter to High/Critical candidates unless all_severities
    if all_severities:
        candidates = rows[:top_n]
        hc_candidates = [r for r in rows if _is_high_critical(r)]
    else:
        hc_candidates = [r for r in rows if _is_high_critical(r)]
        candidates = hc_candidates[:top_n]

    if not candidates:
        result["status"] = "no_candidates"
        result["verdict"] = "no_candidates"
        result["candidate_rows"] = []
        result["summary"] = {
            "total_candidates": len(rows),
            "high_critical_candidates": len(hc_candidates),
            "evaluated": 0,
            "pass_count": 0,
            "blocked_count": 0,
            "waived_count": 0,
            "advisory_count": 0,
            "hard_blocked_predicate_counts": {},
        }
        result["warnings"] = [
            f"no High/Critical candidates in top {top_n} rows "
            f"(total rows: {len(rows)}; use --all-severities to include all)"
        ]
        return result

    # Load gate and active levels
    gate = _load_gate()
    active_levels, inv_meta = _gate_active_levels(gate, inventory_path)

    result["inventory"] = inv_meta

    # Load waivers
    waivers = _load_waivers(auditooor_dir)

    # Per-candidate evaluation
    verdicts: list[dict[str, Any]] = []
    predicate_counts: dict[str, int] = {}

    for idx, row in enumerate(candidates):
        verdict_row = evaluate_candidate(
            row,
            gate=gate,
            active_levels=active_levels,
            waivers=waivers,
            queue_path=queue_path,
            idx=idx,
        )
        verdicts.append(verdict_row)
        for blocker in verdict_row["hard_blockers"]:
            pred = blocker["predicate"]
            predicate_counts[pred] = predicate_counts.get(pred, 0) + 1

    pass_count = sum(1 for v in verdicts if v["status"] == "pass")
    blocked_count = sum(1 for v in verdicts if v["status"] == "blocked")
    waived_count = sum(1 for v in verdicts if v["status"] == "waived")
    advisory_count = sum(1 for v in verdicts if v["advisory_warnings"])

    has_unwaived_blockers = blocked_count > 0
    overall_status = "fail" if has_unwaived_blockers else "pass"
    overall_verdict = "blocked" if has_unwaived_blockers else "pass"

    result["status"] = overall_status
    result["verdict"] = overall_verdict
    result["candidate_rows"] = verdicts
    result["summary"] = {
        "total_candidates": len(rows),
        "high_critical_candidates": len(hc_candidates),
        "evaluated": len(candidates),
        "pass_count": pass_count,
        "blocked_count": blocked_count,
        "waived_count": waived_count,
        "advisory_count": advisory_count,
        "hard_blocked_predicate_counts": predicate_counts,
    }
    result["warnings"] = []

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _human_report(result: dict[str, Any]) -> str:
    lines: list[str] = []
    status = result.get("status", "unknown")
    context = result.get("context", "")
    lines.append(f"pre-poc-lesson-gate [{context}] status={status}")
    lines.append(f"workspace: {result.get('workspace')}")
    summary = result.get("summary") or {}
    lines.append(
        f"  evaluated {summary.get('evaluated', 0)} of "
        f"{summary.get('high_critical_candidates', 0)} High/Critical candidates "
        f"(total rows: {summary.get('total_candidates', 0)})"
    )
    lines.append(
        f"  pass={summary.get('pass_count', 0)} "
        f"blocked={summary.get('blocked_count', 0)} "
        f"waived={summary.get('waived_count', 0)} "
        f"advisory={summary.get('advisory_count', 0)}"
    )
    for row in result.get("candidate_rows") or []:
        cid = row.get("candidate_id", "?")
        sev = row.get("likely_severity", "?")
        verdict = row.get("verdict", "?")
        title = row.get("title", "")[:60]
        lines.append(f"  [{cid}] {sev:8s} {verdict:30s} {title}")
        for b in row.get("hard_blockers") or []:
            lines.append(f"    BLOCKER: {b['predicate']} ({b.get('enforcement_level')})")
            for obl in (b.get("suggested_proof_obligations") or [])[:2]:
                lines.append(f"      -> {obl}")
        for w in row.get("waivers_applied") or []:
            lines.append(f"    WAIVED:  {w['predicate']} by {w.get('waiver_owner')} - {w.get('waiver_reason')}")
    for warn in result.get("warnings") or []:
        lines.append(f"  WARN: {warn}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Pre-PoC lesson gate (J5b) - evaluate each High/Critical exploit-queue "
            "candidate as a structured object against outcome-lesson predicates before "
            "harness/proof work. Callable in prove-top-leads and exploit-conversion-loop contexts."
        ),
    )
    parser.add_argument("--workspace", required=True, help="Path to audit workspace directory.")
    parser.add_argument("--top-n", type=int, default=10, help="Max High/Critical candidates to evaluate (default 10).")
    parser.add_argument(
        "--context",
        choices=["prove-top-leads", "exploit-conversion-loop"],
        default="prove-top-leads",
        help="Calling context tag (default: prove-top-leads).",
    )
    parser.add_argument(
        "--all-severities",
        action="store_true",
        help="Evaluate all severities, not just High/Critical.",
    )
    parser.add_argument(
        "--inventory",
        help="Path to lesson-enforcement-inventory.json (optional; workspace default used if omitted).",
    )
    parser.add_argument(
        "--out-json",
        help="Write JSON result to this path in addition to stdout.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when any evaluated candidate is blocked by a hard predicate with no valid waiver.",
    )
    parser.add_argument(
        "--json",
        dest="emit_json",
        action="store_true",
        help="Emit JSON to stdout (default: human-readable).",
    )
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(f"[pre-poc-lesson-gate] ERR workspace not found or not a directory: {workspace}", file=sys.stderr)
        return 2

    inventory_path = Path(args.inventory).expanduser().resolve() if args.inventory else None

    result = run_gate(
        workspace,
        top_n=args.top_n,
        context=args.context,
        strict=args.strict,
        all_severities=args.all_severities,
        inventory_path=inventory_path,
    )

    if args.out_json:
        out_path = Path(args.out_json).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2, sort_keys=False) + "\n", encoding="utf-8")

    if args.emit_json:
        print(json.dumps(result, indent=2, sort_keys=False))
    else:
        print(_human_report(result))

    if args.strict and result.get("status") == "fail":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
