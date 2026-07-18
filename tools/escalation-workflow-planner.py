#!/usr/bin/env python3
"""escalation-workflow-planner.py - the "can we escalate this bug?" orchestrator.

ALWAYS-CALLED when a finding sits below its max reachable in-scope tier. Given a
finding (a draft, or a mechanism + current tier), it:
  1. reads the ws SEVERITY.md -> the ranked in-scope impact rows;
  2. enumerates the candidate HIGHER in-scope impacts (every rubric row strictly
     above the finding's current tier), each crosswalked to an
     impact_mechanism_library.json class + the documented mechanisms that produce
     it (so the escalation lane is grounded in the library, not ad hoc);
  3. emits ONE escalation LANE per candidate - a ready-to-dispatch adversarial
     brief instructing a worker to PROVE the higher impact end-to-end (PoC) OR
     produce a code-cited proof-of-impossibility (guard/bound/recovery file:line);
  4. LOGS a `planned` record to <ws>/.auditooor/escalation_attempts.jsonl.

The lanes are meant to be dispatched as a MULTI-AGENT WORKFLOW (>= 2 independent
verification lanes per candidate - one to prove, one to refute) via the canonical
spawn-worker rail, then closed with `finalize`. The companion gate
(escalation-workflow-required-check.py) fails a sub-max finding that has no
`resolved` multi-lane record - so the workflow is enforced, not optional.

Actions:
  plan      (default) enumerate candidates + emit lanes + log a `planned` record.
  finalize  write a `resolved` record from a candidate-verdicts JSON (each
            candidate carrying its verdict + >=2 verification_lanes + evidence).
  show      print the latest ledger record for a finding.

Generic, language-agnostic, no network, no source mutation.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.escalation_ledger import (  # noqa: E402
    SCHEMA_VERSION,
    append_ledger,
    crosswalk_row_to_impact_class,
    finding_id_for,
    higher_in_scope_targets,
    infer_tier,
    latest_record_for,
    load_impact_library,
    max_reachable_tier,
    parse_severity_rows,
    record_is_resolved,
    tier_rank,
)


def _draft_sha(draft: Path) -> str:
    import hashlib
    try:
        return hashlib.sha256(draft.read_bytes()).hexdigest()
    except OSError:
        return ""

REPO_ROOT = Path(__file__).resolve().parent.parent

_TIER_IN_TITLE_RE = None


def _now(now: str | None) -> str:
    if now:
        return now
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _infer_current_tier(draft: Path) -> str | None:
    """Best-effort read of the draft's claimed severity tier (shared inference)."""
    if not draft or not draft.is_file():
        return None
    return infer_tier(draft.read_text(encoding="utf-8", errors="replace"))


# Impact classes / rubric-row phrasings that describe a CRASH / HALT / liveness escalation.
# When a finding escalates toward one of these, a proof-of-impossibility that rests on a
# deployment/topology assumption (e.g. "validators are sentry-shielded") is INSUFFICIENT
# until the crashing component's process blast-radius is established from source.
_CRASH_IMPACT_KEYS = frozenset({
    "bc-rpc-api-crash", "rpc_crash_high", "rpc_crash", "validator_crash",
    "chain-halt-shutdown", "chain_halt", "chain-split-fork", "chain_split",
    "node-crash", "liveness-loss", "block-production-delay",
})
_CRASH_ROW_RX = re.compile(
    r"crash|halt|liveness|chain split|network partition|block production delay|"
    r"denial of service|\bdos\b|validator",
    re.I,
)


def _is_crash_escalation(cand: dict) -> bool:
    key = (cand.get("impact_class") or "").lower()
    if key in _CRASH_IMPACT_KEYS:
        return True
    return bool(_CRASH_ROW_RX.search(cand.get("severity_row") or ""))


def _blast_radius_clause(cand: dict) -> str:
    """For a crash/halt/liveness escalation target, force the verifier to establish the
    crashing component's PROCESS BLAST RADIUS from source before accepting any
    deployment-assumption proof-of-impossibility. Root lesson (SEI evmrpc filter-DoS,
    2026-07-05): an RPC-node-crash was bounded to Medium on the assumption that
    'validators do not expose the endpoint', WITHOUT first checking that the RPC server
    runs IN THE SAME OS PROCESS as the consensus engine (app.go NewEVM*Server) - a
    co-located crash kills consensus too, and the ONLY honest bound on the higher tier is
    then the rubric's OWN qualifier, cited, not a bare topology guess."""
    if not _is_crash_escalation(cand):
        return ""
    return (
        "- PROCESS-COLOCATION / BLAST-RADIUS (MANDATORY for this crash/halt/liveness "
        "escalation): BEFORE accepting any proof-of-impossibility that rests on a "
        "deployment/topology assumption (e.g. 'validators are sentry-shielded', 'the "
        "endpoint is not exposed', 'runs on a separate node'), you MUST first establish "
        "the CODE FACT of the crashing component's blast radius. Grep the app / node "
        "bootstrap (e.g. app.go / cmd/*/root.go / start.go) for where the vulnerable "
        "server/component is CONSTRUCTED and STARTED, and determine: does the crashing "
        "OS process ALSO host a higher-value role (consensus/ABCI engine, validator "
        "signer, sequencer, block producer)? If SAME-PROCESS (e.g. the RPC server is "
        "built inside the consensus app and shares its BaseApp/keepers), then an "
        "OOM/panic is a WHOLE-NODE crash including consensus - and the only thing "
        "bounding the higher (validator-crash / liveness / chain-split) tier is the "
        "rubric's OWN explicit qualifier. In that case your proof-of-impossibility MUST "
        "cite BOTH (i) the colocation code file:line AND (ii) the exact rubric qualifier "
        "line (e.g. 'assuming no direct network access to validator nodes' / 'via "
        "crafted [consensus] messages' / 'via propagated block/tx payloads'), and show "
        "the finding's vector cannot satisfy that qualifier. If the crash IS genuinely "
        "process-isolated from consensus, cite the separate-process/separate-binary boot "
        "code that proves it. A bare 'validators are shielded' assertion WITHOUT the "
        "colocation code fact is REJECTED (it under-bounds a real amplifier).\n"
    )


_PROOF_DISCIPLINE_CLAUSE = (
    "- PROOF-OF-IMPOSSIBILITY DISCIPLINE (MANDATORY, ALL escalation tiers - not just "
    "crashes): a bound is only valid if it is (i) a CODE GUARD at an exact in-scope "
    "file:line that structurally caps the impact, (ii) a NUMERIC or ECONOMIC bound WITH "
    "UNITS derived from source (e.g. 'capped at MaxUint64 at x.go:12', 'refund <= "
    "principal, y.go:44'), (iii) a NAMED in-protocol recovery mechanism (a specific "
    "revert/recover/rollback/slash at file:line), OR (iv) the rubric's OWN explicit "
    "qualifier quoted verbatim from SEVERITY.md with a shown reason the finding's vector "
    "cannot satisfy it. The following are FORBIDDEN as a proof-of-impossibility and are "
    "REJECTED by the gate: a bare DEPLOYMENT/TOPOLOGY assumption ('validators are "
    "sentry-shielded', 'the endpoint is firewalled', 'runs on a separate node'), a "
    "BENIGN-CONFIG assumption ('the admin would not set it that way', 'default config is "
    "safe' without citing the enforcing code), an ATTACKER-CAPABILITY assumption ('an "
    "attacker cannot reach / cannot afford / would not bother') absent a code/economic "
    "cite, a GOVERNANCE assumption ('governance would not pass a malicious proposal') "
    "when the rubric does not itself grant it, and 'too hard to build' / 'reasoning "
    "only'. If your only bound is an assumption, you have NOT proven impossibility - "
    "escalate or keep the tier OPEN.\n"
)


def _lane_brief(idx: int, cand: dict, lib: dict, finding_desc: str, ws: str) -> str:
    key = cand.get("impact_class")
    mechs = lib.get(key, []) if key else []
    mech_lines = "\n".join(
        f"    - {m.get('mechanism')} (langs: {','.join(m.get('languages', []))})"
        for m in mechs[:8]
    ) or "    - (no library mechanisms mapped; reason from first principles)"
    return (
        f"### Escalation lane {idx}: -> {cand['tier'].upper()} \"{cand['severity_row']}\"\n"
        f"- workspace: {ws}\n"
        f"- finding under review: {finding_desc}\n"
        f"- target in-scope impact (VERBATIM rubric row): {cand['severity_row']}\n"
        f"- library impact class: {key or 'UNMAPPED'}\n"
        f"- documented mechanisms that PRODUCE this impact (from impact_mechanism_library.json):\n{mech_lines}\n"
        f"- TASK: attempt to escalate THIS finding's mechanism to the target impact "
        f"end-to-end. Either (a) PROVE it with a runnable PoC that exhibits the "
        f"target impact, OR (b) produce a code-cited PROOF-OF-IMPOSSIBILITY (a guard "
        f"at file:line that structurally caps it / a numeric-or-economic bound with "
        f"units / a named in-protocol recovery mechanism). 'Too hard to build' / "
        f"'reasoning-only' is NOT a valid fallback (fails the gate).\n"
        f"- ADVERSARIAL: this lane is one of >=2 independent lanes per candidate "
        f"(prove-lane + refute-lane). Record each lane's verdict.\n"
        + _PROOF_DISCIPLINE_CLAUSE
        + _blast_radius_clause(cand)
    )


def cmd_plan(args) -> int:
    ws = Path(args.workspace).resolve()
    sev_md = Path(args.severity_md) if args.severity_md else (ws / "SEVERITY.md")
    rows = parse_severity_rows(sev_md)
    if not rows:
        print(json.dumps({"gate": "ESCALATION-WORKFLOW-PLAN", "verdict": "no-severity-rows",
                          "severity_md": str(sev_md)}) if args.json
              else f"[escalation-plan] no rubric rows parsed from {sev_md} - cannot plan")
        return 2

    draft = Path(args.draft).resolve() if args.draft else None
    current_tier = (args.current_tier or (_infer_current_tier(draft) if draft else None) or "").lower()
    if not current_tier:
        print("[escalation-plan] could not determine current tier; pass --current-tier", file=sys.stderr)
        return 2

    finding_id = finding_id_for(draft, ws) if draft else (args.finding_id or f"adhoc:{args.mechanism[:40]}")
    finding_desc = args.mechanism or (finding_id if draft else "")
    lib = load_impact_library(REPO_ROOT)

    targets = higher_in_scope_targets(current_tier, rows)
    max_tier = max_reachable_tier(rows)

    if not targets:
        # Finding already at the top of the rubric - nothing to escalate to.
        rec = {
            "schema": SCHEMA_VERSION, "finding_id": finding_id, "finding_desc": finding_desc,
            "current_tier": current_tier, "max_reachable_tier": max_tier,
            "candidate_targets": [], "status": "resolved",
            "resolution": "at-max-tier-nothing-higher", "planned_at": _now(args.now),
            "resolved_at": _now(args.now), "planner": "escalation-workflow-planner.py",
        }
        if not args.dry_run:
            append_ledger(ws, rec)
        out = {"gate": "ESCALATION-WORKFLOW-PLAN", "verdict": "at-max-tier",
               "finding_id": finding_id, "current_tier": current_tier, "candidate_count": 0}
        print(json.dumps(out) if args.json else
              f"[escalation-plan] {finding_id} is at the max in-scope tier ({current_tier}); "
              f"nothing higher to escalate to. Logged resolved(at-max-tier).")
        return 0

    candidate_targets = [
        {"impact_class": t["impact_class"], "severity_row": t["severity_row"],
         "tier": t["tier"], "verdict": "open", "verification_lanes": [], "evidence": ""}
        for t in targets
    ]
    rec = {
        "schema": SCHEMA_VERSION, "finding_id": finding_id, "finding_desc": finding_desc,
        "current_tier": current_tier, "max_reachable_tier": max_tier,
        "candidate_targets": candidate_targets, "status": "planned",
        "planned_at": _now(args.now), "planner": "escalation-workflow-planner.py",
    }
    if not args.dry_run:
        append_ledger(ws, rec)

    if args.json:
        print(json.dumps({"gate": "ESCALATION-WORKFLOW-PLAN", "verdict": "planned",
                          "finding_id": finding_id, "current_tier": current_tier,
                          "max_reachable_tier": max_tier,
                          "candidate_count": len(targets),
                          "candidates": [t["severity_row"] for t in targets]}))
        return 0

    print(f"# Escalation workflow plan for {finding_id}")
    print(f"# current tier: {current_tier}  |  max in-scope tier: {max_tier}  |  "
          f"{len(targets)} higher target(s)")
    print(f"# Logged `planned` to {ws}/.auditooor/escalation_attempts.jsonl")
    print(f"# Dispatch each lane below (>=2 independent lanes/candidate: prove + refute) "
          f"via the canonical spawn-worker rail, then run `finalize`.\n")
    for i, cand in enumerate(targets, 1):
        print(_lane_brief(i, cand, lib, finding_desc or finding_id, str(ws)))
    return 0


def cmd_finalize(args) -> int:
    """Write a `resolved` record from a candidate-verdicts JSON file/stdin.
    Expected shape: {"finding_id": "...", "current_tier": "...", "final_tier":
    "...", "candidate_targets": [{"severity_row","impact_class","tier","verdict",
    "evidence","verification_lanes":[{"lane_id","agent","verdict"},...]}, ...]}"""
    ws = Path(args.workspace).resolve()
    raw = sys.stdin.read() if args.verdicts == "-" else Path(args.verdicts).read_text(encoding="utf-8")
    payload = json.loads(raw)
    finding_id = payload.get("finding_id") or args.finding_id
    draft = Path(args.draft).resolve() if args.draft else None
    if draft and not finding_id:
        finding_id = finding_id_for(draft, ws)
    if not finding_id:
        print("[escalation-finalize] finding_id required (in JSON or --finding-id or --draft)", file=sys.stderr)
        return 2
    # content-binding (rank-5): store the draft hash so a later in-place edit
    # invalidates this resolved record. planned_at carried from the plan record.
    draft_sha = _draft_sha(draft) if draft else payload.get("draft_content_sha256", "")
    prior = latest_record_for(ws, finding_id) or {}
    rec = {
        "schema": SCHEMA_VERSION, "finding_id": finding_id,
        "finding_desc": payload.get("finding_desc", ""),
        "current_tier": payload.get("current_tier", ""),
        "max_reachable_tier": payload.get("max_reachable_tier", ""),
        "final_tier": payload.get("final_tier", payload.get("current_tier", "")),
        "candidate_targets": payload.get("candidate_targets", []),
        "status": "resolved",
        "draft_content_sha256": draft_sha,
        "planned_at": payload.get("planned_at") or prior.get("planned_at", ""),
        "resolved_at": _now(args.now),
        "workflow_run_id": payload.get("workflow_run_id", ""),
        "planner": "escalation-workflow-planner.py",
    }
    ok, reason, failures = record_is_resolved(rec, ws=ws)
    if not args.dry_run:
        append_ledger(ws, rec)
    out = {"gate": "ESCALATION-WORKFLOW-FINALIZE", "finding_id": finding_id,
           "resolved_terminal": ok, "reason": reason, "candidate_failures": failures}
    print(json.dumps(out) if args.json else
          f"[escalation-finalize] {finding_id}: resolved-record written; "
          f"terminal={ok} ({reason})" + (f"; failures={failures}" if failures else ""))
    return 0 if ok else 1


def cmd_show(args) -> int:
    ws = Path(args.workspace).resolve()
    rec = latest_record_for(ws, args.finding_id)
    print(json.dumps(rec, indent=2) if rec else f"[escalation-show] no record for {args.finding_id}")
    return 0 if rec else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", nargs="?", default="plan", choices=["plan", "finalize", "show"])
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--draft", help="path to the finding draft markdown")
    ap.add_argument("--finding-id", help="explicit finding id (else derived from --draft)")
    ap.add_argument("--current-tier", help="critical|high|medium|low (else inferred from --draft)")
    ap.add_argument("--mechanism", default="", help="one-line mechanism summary for the lane briefs")
    ap.add_argument("--severity-md", help="override path to SEVERITY.md")
    ap.add_argument("--verdicts", default="-", help="finalize: path to candidate-verdicts JSON (or - for stdin)")
    ap.add_argument("--now", help="freeze timestamp (tests)")
    ap.add_argument("--dry-run", action="store_true", help="do not write the ledger")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if args.action == "plan":
        return cmd_plan(args)
    if args.action == "finalize":
        return cmd_finalize(args)
    return cmd_show(args)


if __name__ == "__main__":
    raise SystemExit(main())
