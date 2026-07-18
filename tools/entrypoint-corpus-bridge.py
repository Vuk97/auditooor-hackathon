#!/usr/bin/env python3
"""entrypoint-corpus-bridge.py - terminal-close corpus-INV `blocked_missing_truth` AND
`blocked_admin_gated_or_by_design` exploit-queue rows that are PROVABLY
non-attacker-reachable (non-entry-point) helpers.

Why this exists (the backlog it drains)
---------------------------------------
`candidate-judgment-packet.py` grounds every corpus-INV exploit-queue lead into a
judgment packet. On a Cosmos/Go-L1 like axelar-dlt, ~4.6k packets land in
``packet_state=blocked_missing_truth`` and block ``prove-top-leads`` STRICT. The vast
majority trace to a handful of NON-attacker-reachable functions -
``InitWasmHooks`` / ``RegisterTendermintService`` / ``InitModuleAccountPermissions`` /
``initMessageRouter`` / ``GetMsgV1Signers`` - genesis/app-init/registration/read-only
helpers already EXCLUDED from the function-coverage denominator by the authoritative
``go_entrypoint_surface`` classifier. For such a function, "there is no permissionless
trigger" is not a *missing* fact to hunt down - it is the TERMINAL-NEGATIVE fact: an
internal helper reached only THROUGH an entry point has no direct attacker surface, so
a corpus-INV lead demanding "who is the attacker / what is the permissionless trigger"
is answered by "none - not an entry point".

This bridge reports (and, only under ``--write``, applies) a ``closed_negative`` proof
status for exactly those rows - and NOTHING else.

HARD SAFETY INVARIANTS (this tool must NEVER false-green / hide a real bug)
--------------------------------------------------------------------------
A row is eligible to close ONLY when ALL of:

  (1) the function is PROVABLY NOT in the Go entry surface, per the AUTHORITATIVE
      classifier ``go_entrypoint_surface.is_go_entry_point`` (reused, not reinvented) -
      evaluated over the function's REAL Go declaration(s) on disk. If the workspace is
      not a Cosmos/Go-L1 (``is_cosmos_go_workspace`` False), or the declaration cannot
      be located, or ANY declaration classifies as an entry point, the row is KEPT OPEN.
  (2) the packet carries the STATE-APPROPRIATE terminal-negative promotion-blocker marker:
      ``missing:permissionless_trigger`` / ``missing:attacker_actor`` for a
      ``blocked_missing_truth`` row, or ``admin_gated_or_by_design`` for a
      ``blocked_admin_gated_or_by_design`` row. No marker -> KEPT OPEN. The admin-gated
      marker is CORROBORATING, never sufficient alone (an admin gate can hide a
      privilege-escalation on a real entry point) - invariant (1)'s non-entry classifier
      verdict is the load-bearing gate for BOTH states.
  (3) the row is not already a real finding / terminal (proof_status not proven / filed /
      confirmed / already-closed). Already-terminal -> KEPT OPEN (never re-close).

Never on attack_class or name-heuristic alone; never an entry-point row; never a
marker-less row. DEFAULT is DRY-RUN: terminal writes happen ONLY under ``--write``.

Solidity / non-Cosmos-Go workspaces are a safe NO-OP (no Go entry classifier applies ->
zero closes), by construction of invariant (1).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Optional

_TOOLS = Path(__file__).resolve().parent

# The missing-trigger markers that make "no permissionless trigger" a terminal-negative
# fact for a non-entry-point helper (invariant 2) - for ``blocked_missing_truth`` rows.
MISSING_TRIGGER_MARKERS = frozenset(
    {"missing:permissionless_trigger", "missing:attacker_actor"}
)

# The admin-gated / by-design marker that makes "no permissionless attacker trigger" a
# terminal-negative fact for a non-entry-point helper reached only under an admin gate or
# by-design boot path (invariant 2) - for ``blocked_admin_gated_or_by_design`` rows. NOTE:
# this marker is NOT sufficient ALONE - an admin gate can hide a privilege-escalation on a
# REAL entry point. The hard gate remains invariant (1): the AUTHORITATIVE non-entry-point
# classifier verdict. We only ever close when BOTH the marker AND the classifier agree.
ADMIN_GATED_MARKERS = frozenset({"admin_gated_or_by_design"})

# The blocked packet states this bridge drains. Each maps to its terminal-negative marker
# set; the classifier gate (invariant 1) is IDENTICAL for every state.
BLOCKED_STATE_MARKERS = {
    "blocked_missing_truth": MISSING_TRIGGER_MARKERS,
    "blocked_admin_gated_or_by_design": ADMIN_GATED_MARKERS,
}
BLOCKED_STATES = frozenset(BLOCKED_STATE_MARKERS)

# proof_status / quality values that mean the row is ALREADY terminal (positive or
# negative) - never re-close one of these (invariant 3).
ALREADY_TERMINAL_STATUSES = frozenset(
    {
        "proven",
        "filed",
        "confirmed",
        "paste_ready",
        "paste-ready",
        "accepted",
        "killed",
        "kill",
        "drop",
        "dropped",
        "disproved",
        "closed_negative",
        "closed_negative_operator_review",
        "closed_negative_source_proof",
        "false_positive",
        "false-positive",
        "not_exploitable",
        "not_candidate",
        "refuted",
        "disqualified",
    }
)

CLOSED_STATUS = "closed_negative"


def _load_go_entrypoint_surface():
    """Import the AUTHORITATIVE classifier module (reuse, do not reinvent)."""
    spec = importlib.util.spec_from_file_location(
        "ges_bridge", str(_TOOLS / "go_entrypoint_surface.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _read_json(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def _parse_dupe_triple(packet: dict) -> tuple[Optional[str], Optional[str]]:
    """Return (contract_rel_path, function_name) from a packet.

    Primary source is ``required_judgment_fields.dupe_triple`` which is a
    ``contract=... | function=... | attack_class=...`` string; falls back to
    ``impact_enumeration.function`` for the function name.
    """
    contract = None
    fn = None
    rjf = packet.get("required_judgment_fields") or {}
    dt = rjf.get("dupe_triple") or ""
    if isinstance(dt, str):
        for seg in dt.split("|"):
            seg = seg.strip()
            if seg.startswith("contract="):
                contract = seg[len("contract="):].strip() or None
            elif seg.startswith("function="):
                fn = seg[len("function="):].strip() or None
    if not fn:
        ie = packet.get("impact_enumeration") or {}
        fn = ie.get("function") or None
    return contract, fn


def _find_go_declarations(ws: Path, contract: Optional[str], fn: str, G) -> Optional[list]:
    """Locate Go declarations of ``fn`` in ``contract``.

    Returns a list of (receiver, rel_path, sig) tuples, or ``None`` when the file is
    unknown / missing / not a ``.go`` file (caller treats ``None`` as "cannot prove
    non-entry" -> KEEP OPEN).
    """
    if not contract or not contract.endswith(".go"):
        return None
    fpath = ws / contract
    if not fpath.is_file():
        return None
    try:
        lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return None
    pat = re.compile(r"func\b.*\b" + re.escape(fn) + r"\s*\(")
    out = []
    for i, line in enumerate(lines):
        if pat.search(line):
            sig = "\n".join(lines[i : i + 3])
            receiver = G.extract_go_receiver(line)
            out.append((receiver, contract, sig))
    return out


def _is_already_terminal(row: dict) -> bool:
    status = str(
        row.get("proof_status")
        or row.get("source_mined_proof_status")
        or row.get("proof_verdict")
        or row.get("status")
        or ""
    ).strip().lower()
    quality = str(row.get("quality_gate_status") or "").strip().lower()
    if status in ALREADY_TERMINAL_STATUSES:
        return True
    if quality in ALREADY_TERMINAL_STATUSES or quality.startswith("closed_negative"):
        return True
    return False


def classify_packet(
    packet: dict,
    ws: Path,
    queue_index: dict,
    go_applies: bool,
    G,
) -> dict:
    """Classify one packet -> a decision record.

    decision in {"close", "keep-entry-point", "keep-no-marker",
                 "keep-unresolved-decl", "keep-non-go-workspace",
                 "keep-already-terminal", "keep-no-queue-row", "skip-not-blocked"}
    Only ``close`` is eligible for a terminal ``closed_negative`` write.
    """
    contract, fn = _parse_dupe_triple(packet)
    lead_id = packet.get("candidate_id")
    state = packet.get("packet_state")
    # State-appropriate terminal-negative marker set (invariant 2). A row in a state we do
    # not drain has an empty required set -> marker_present False -> KEPT OPEN.
    required_markers = BLOCKED_STATE_MARKERS.get(state, frozenset())
    blockers = packet.get("promotion_blockers") or []
    marker_present = any(b in required_markers for b in blockers)
    rec = {
        "lead_id": lead_id,
        "function": fn,
        "contract": contract,
        "packet_state": state,
        "marker_present": marker_present,
        "entry_point": None,
        "decision": None,
        "reason": None,
    }

    row = queue_index.get(lead_id)
    if row is None:
        rec["decision"] = "keep-no-queue-row"
        rec["reason"] = "no exploit_queue row for candidate_id"
        return rec

    if _is_already_terminal(row):
        rec["decision"] = "keep-already-terminal"
        rec["reason"] = "row already terminal (finding/closed) - never re-close"
        return rec

    # Invariant (2): must carry the state-appropriate terminal-negative marker.
    if not marker_present:
        rec["decision"] = "keep-no-marker"
        rec["reason"] = (
            f"packet lacks a terminal-negative marker for state {state!r} "
            f"(one of {sorted(required_markers)})"
        )
        return rec

    # Invariant (1): Go entry classifier must apply AND prove non-entry.
    if not go_applies:
        rec["decision"] = "keep-non-go-workspace"
        rec["reason"] = "workspace is not a Cosmos/Go-L1 - no Go entry classifier applies (safe no-op)"
        return rec

    if not fn:
        rec["decision"] = "keep-unresolved-decl"
        rec["reason"] = "could not resolve function name from packet"
        return rec

    decls = _find_go_declarations(ws, contract, fn, G)
    if not decls:  # None or empty -> cannot prove non-entry -> KEEP OPEN
        rec["decision"] = "keep-unresolved-decl"
        rec["reason"] = "could not locate Go declaration on disk - cannot prove non-entry"
        return rec

    is_entry = any(
        G.is_go_entry_point(fn, receiver, rel, sig) for receiver, rel, sig in decls
    )
    rec["entry_point"] = is_entry
    if is_entry:
        rec["decision"] = "keep-entry-point"
        rec["reason"] = "AUTHORITATIVE classifier: function IS a Go entry point (attacker-reachable) - MUST NOT close"
        return rec

    marker = next(
        (b for b in blockers if b in required_markers),
        sorted(required_markers)[0] if required_markers else "missing:permissionless_trigger",
    )
    receiver0, rel0, _ = decls[0]
    rec["decision"] = "close"
    if state == "blocked_admin_gated_or_by_design":
        gate_phrase = (
            "an admin gate / by-design boot path over a NON-entry-point internal helper has "
            "no permissionless attacker trigger (the admin marker is corroborating, NOT "
            "sufficient - the classifier verdict is the load-bearing gate)"
        )
    else:
        gate_phrase = (
            "no permissionless trigger IS the terminal-negative fact for an internal helper "
            "reached only through an entry point"
        )
    rec["reason"] = (
        f"non-entry-point helper (go_entrypoint_surface.is_go_entry_point=False for "
        f"{fn} @ {rel0}); state {state}; marker {marker}: {gate_phrase}"
    )
    rec["source_ref"] = rel0
    return rec


def build_plan(ws: Path) -> dict:
    """Build the full dry-run plan for a workspace (no mutation)."""
    G = _load_go_entrypoint_surface()
    go_applies = bool(G.is_cosmos_go_workspace(ws))

    packet_path = ws / ".auditooor" / "prove_top_leads_candidate_judgment_packet.json"
    queue_path = ws / ".auditooor" / "exploit_queue.json"
    pj = _read_json(packet_path)
    qj = _read_json(queue_path)

    plan: dict[str, Any] = {
        "schema": "auditooor.entrypoint_corpus_bridge.v1",
        "workspace": str(ws),
        "go_entry_classifier_applies": go_applies,
        "packet_artifact_present": pj is not None,
        "queue_artifact_present": qj is not None,
        "decisions": [],
        "per_function_close_counts": {},
        "per_function_entry_verdict": {},
        "counts": {},
        "would_close_lead_ids": [],
    }

    if pj is None or qj is None:
        plan["counts"] = {"error": "missing packet or queue artifact"}
        return plan

    queue_rows = qj.get("queue") if isinstance(qj, dict) else qj
    if not isinstance(queue_rows, list):
        plan["counts"] = {"error": "unexpected exploit_queue shape"}
        return plan
    queue_index = {r.get("lead_id"): r for r in queue_rows if isinstance(r, dict)}

    packets = pj.get("packets") if isinstance(pj, dict) else pj
    blocked = [
        p
        for p in (packets or [])
        if isinstance(p, dict) and p.get("packet_state") in BLOCKED_STATES
    ]

    from collections import Counter

    close_counts: Counter = Counter()
    decision_counts: Counter = Counter()
    state_counts: Counter = Counter()
    close_by_state: Counter = Counter()
    entry_verdict: dict[str, bool] = {}

    for p in blocked:
        state_counts[p.get("packet_state")] += 1
        rec = classify_packet(p, ws, queue_index, go_applies, G)
        decision_counts[rec["decision"]] += 1
        fn = rec.get("function")
        if rec.get("entry_point") is not None and fn:
            # last-writer-wins is fine; a function is either entry or not deterministically
            entry_verdict[fn] = rec["entry_point"]
        if rec["decision"] == "close":
            close_counts[fn] += 1
            close_by_state[rec.get("packet_state")] += 1
            plan["would_close_lead_ids"].append(rec["lead_id"])
            plan["decisions"].append(rec)
        elif rec["decision"] == "keep-entry-point":
            # keep the loud safety record for entry-point refusals
            plan["decisions"].append(rec)

    plan["per_function_close_counts"] = dict(close_counts.most_common())
    plan["per_function_entry_verdict"] = entry_verdict
    plan["per_state_blocked_counts"] = dict(state_counts)
    plan["per_state_close_counts"] = dict(close_by_state)
    plan["counts"] = {
        "blocked_total": len(blocked),
        "blocked_missing_truth_total": state_counts.get("blocked_missing_truth", 0),
        "blocked_admin_gated_total": state_counts.get(
            "blocked_admin_gated_or_by_design", 0
        ),
        "would_close": sum(close_counts.values()),
        "would_close_missing_truth": close_by_state.get("blocked_missing_truth", 0),
        "would_close_admin_gated": close_by_state.get(
            "blocked_admin_gated_or_by_design", 0
        ),
        "kept_open": len(blocked) - sum(close_counts.values()),
        "kept_entry_point": decision_counts.get("keep-entry-point", 0),
        "kept_no_marker": decision_counts.get("keep-no-marker", 0),
        "kept_unresolved_decl": decision_counts.get("keep-unresolved-decl", 0),
        "kept_non_go_workspace": decision_counts.get("keep-non-go-workspace", 0),
        "kept_already_terminal": decision_counts.get("keep-already-terminal", 0),
        "kept_no_queue_row": decision_counts.get("keep-no-queue-row", 0),
        "decision_breakdown": dict(decision_counts),
    }
    return plan


def apply_plan(ws: Path, plan: dict) -> int:
    """Apply the terminal closures to exploit_queue.json (ONLY under --write).

    Sets proof_status=closed_negative + a cited reason on each eligible row. Returns
    the number of rows mutated. Never touches a row not in the plan's close set.
    """
    queue_path = ws / ".auditooor" / "exploit_queue.json"
    qj = _read_json(queue_path)
    if not isinstance(qj, dict):
        return 0
    queue_rows = qj.get("queue")
    if not isinstance(queue_rows, list):
        return 0
    reason_by_lead = {d["lead_id"]: d for d in plan.get("decisions", []) if d.get("decision") == "close"}
    index = {r.get("lead_id"): r for r in queue_rows if isinstance(r, dict)}
    mutated = 0
    for lead_id, dec in reason_by_lead.items():
        row = index.get(lead_id)
        if row is None or _is_already_terminal(row):
            continue
        row["proof_status"] = CLOSED_STATUS
        row["quality_gate_status"] = CLOSED_STATUS
        row["entrypoint_corpus_bridge"] = {
            "closed": True,
            "entry_point": False,
            "function": dec.get("function"),
            "marker": True,
            "reason": dec.get("reason"),
            "source_ref": dec.get("source_ref"),
        }
        mutated += 1
    if mutated:
        queue_path.write_text(json.dumps(qj, indent=1), encoding="utf-8")
    return mutated


TOP_FUNCTIONS = [
    "InitWasmHooks",
    "RegisterTendermintService",
    "InitModuleAccountPermissions",
    "initMessageRouter",
    "GetMsgV1Signers",
    # crypto_signing admin-gated functions - loud verdict so a signing ENTRY point can
    # never slip through as a silent close.
    "NewSignature",
    "getSigner",
]


def _print_report(plan: dict, wrote: Optional[int]) -> None:
    c = plan.get("counts", {})
    print("=" * 72)
    print("entrypoint-corpus-bridge  (DRY-RUN)" if wrote is None else "entrypoint-corpus-bridge  (--write APPLIED)")
    print("=" * 72)
    print(f"workspace                : {plan['workspace']}")
    print(f"go entry classifier      : {'APPLIES (Cosmos/Go-L1)' if plan['go_entry_classifier_applies'] else 'DOES NOT APPLY (non-Cosmos-Go -> safe no-op)'}")
    print(f"blocked (all states)     : {c.get('blocked_total')}")
    print(f"  blocked_missing_truth  : {c.get('blocked_missing_truth_total')}  (would-close {c.get('would_close_missing_truth')})")
    print(f"  blocked_admin_gated    : {c.get('blocked_admin_gated_total')}  (would-close {c.get('would_close_admin_gated')})")
    print(f"WOULD-CLOSE (non-entry)  : {c.get('would_close')}")
    print(f"residual KEPT OPEN       : {c.get('kept_open')}")
    print("  kept: entry-point      : %s" % c.get("kept_entry_point"))
    print("  kept: no-marker        : %s" % c.get("kept_no_marker"))
    print("  kept: unresolved-decl  : %s" % c.get("kept_unresolved_decl"))
    print("  kept: already-terminal : %s" % c.get("kept_already_terminal"))
    print("  kept: non-go-workspace : %s" % c.get("kept_non_go_workspace"))
    print("-" * 72)
    print("per-function would-close counts:")
    for fn, n in plan.get("per_function_close_counts", {}).items():
        print(f"  {n:6d}  {fn}")
    print("-" * 72)
    print("TOP-5 function entry-point verdicts (MUST be non-entry to close):")
    ev = plan.get("per_function_entry_verdict", {})
    cc = plan.get("per_function_close_counts", {})
    for fn in TOP_FUNCTIONS:
        verdict = ev.get(fn)
        if verdict is True:
            print(f"  !! LOUD ALARM: {fn} IS an entry point (attacker-reachable) - NOT closed")
        elif verdict is False:
            print(f"  OK non-entry-point: {fn}  (would-close {cc.get(fn, 0)})")
        else:
            print(f"  (not observed among blocked packets): {fn}")
    # Loud global alarm for ANY entry-point among close candidates (should be zero).
    entry_in_close = [fn for fn, v in ev.items() if v is True and fn in cc]
    if entry_in_close:
        print(f"  !!!! FATAL: entry-point function(s) in close set: {entry_in_close}")
    if wrote is not None:
        print("-" * 72)
        print(f"rows mutated -> proof_status=closed_negative : {wrote}")
    print("=" * 72)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--workspace", required=True, help="workspace path")
    ap.add_argument(
        "--write",
        action="store_true",
        help="APPLY terminal closed_negative writes (default is dry-run only)",
    )
    ap.add_argument("--json", action="store_true", help="emit the plan as JSON")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[entrypoint-corpus-bridge] ERR workspace not found: {ws}", file=sys.stderr)
        return 2

    plan = build_plan(ws)

    wrote = None
    if args.write:
        wrote = apply_plan(ws, plan)

    if args.json:
        out = dict(plan)
        if wrote is not None:
            out["rows_mutated"] = wrote
        print(json.dumps(out, indent=1))
    else:
        _print_report(plan, wrote)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
