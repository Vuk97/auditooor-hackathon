#!/usr/bin/env python3
"""impact-first-backward-search.py - NOVELTY-LAYER engine #3 (was MISSING).

Roadmap NOVELTY-GENERATION LAYER item 3: "IMPACT-FIRST BACKWARD SEARCH: start
from a mega-impact (attacker mints / drains / freezes / halts HERE) and search
BACKWARD for a reaching mechanism - do NOT enumerate forward from a shape."

This is a REASONING QUERY over the OWNED go-dataflow / slither substrate
(dataflow_paths.jsonl), not a token detector. For each path whose SINK is a
mega-impact operation, it asks: is that sink reached on an UNGUARDED path that
has an UNGUARDED BACKWARD ENTRYPOINT (an external/unprivileged caller reaches it
with no dominating guard)? The substrate already computes
backward_entrypoints_total / backward_entrypoints_guarded per path; a path with
total > guarded has >=1 entrypoint that reaches the sink without a guard. Those
are the impact-first candidates, ranked by the sink's impact tier.

NOT-A-SHAPE: the query is (mega-impact sink) AND (path unguarded) AND (exists an
unguarded backward entrypoint). It reduces to reachability + guard-dominance over
the dataflow closure, never "token X present/absent".

Advisory-first: emits obligations (impact_backward_obligations.jsonl) that the
hunt must drive to a terminal verdict; it never itself asserts a finding.
"""
import argparse
import json
import pathlib
import sys
from collections import defaultdict

SCHEMA = "auditooor.impact_backward_search.v1"
AUDITOOOR = ".auditooor"

# sink.kind (lowercased) -> impact tier. Backward search STARTS from these.
_IMPACT_TIER = {
    # CRITICAL: attacker-controlled code/asset creation or destruction
    "selfdestruct": "critical", "delegatecall": "critical", "mint": "critical",
    # HIGH: value leaves / is destroyed
    "burn": "high", "value-move": "high", "send": "high", "transfer": "high",
    "safetransfer": "high", "safetransferfrom": "high", "call": "high",
}
_TIER_RANK = {"critical": 3, "high": 2, "medium": 1}

# DIRECTION-AMBIGUOUS sinks: a transfer/call can move value EITHER out of the
# protocol to an attacker (real impact) OR from the caller's own balance into the
# protocol (safeTransferFrom(msg.sender, ...) = benign, self-authorized). The
# substrate does not carry the `from` operand, so the engine cannot decide
# direction; it must NOT claim these are confirmed impact. Flagged
# direction_ambiguous + the search_question forces the hunt to verify the from-
# party. NOT suppressed (a real protocol-drain by msg.sender would also live
# here - suppressing would be a false-negative). mint/burn/delegatecall/
# selfdestruct are protocol-authority ops and are NOT ambiguous. Root-caused
# 2026-07-14: all 6 nuva impact-first candidates were safeTransferFrom(msg.sender,)
# caller-funded deposits/withdrawals (benign).
_DIRECTION_AMBIGUOUS = {"value-move", "send", "transfer", "safetransfer",
                        "safetransferfrom", "call"}


def _adir(ws: pathlib.Path) -> pathlib.Path:
    return ws / AUDITOOOR


def load_paths(ws: pathlib.Path) -> list:
    p = _adir(ws) / "dataflow_paths.jsonl"
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def _has_unguarded_entrypoint(rec: dict) -> bool:
    """A backward entrypoint reaches the sink WITHOUT a dominating guard iff the
    substrate found more total backward entrypoints than guarded ones."""
    try:
        tot = int(rec.get("backward_entrypoints_total") or 0)
        grd = int(rec.get("backward_entrypoints_guarded") or 0)
    except (TypeError, ValueError):
        return False
    return tot > grd


def analyse(ws: pathlib.Path) -> dict:
    paths = load_paths(ws)
    # dedup by (sink file, sink line, sink kind) - one obligation per impact site
    by_site: dict = {}
    substrate_has_backptr = False
    for rec in paths:
        if rec.get("degraded"):
            continue
        sink = rec.get("sink") or {}
        kind = str(sink.get("kind") or "").lower()
        tier = _IMPACT_TIER.get(kind)
        if not tier:
            continue
        if "backward_entrypoints_total" in rec:
            substrate_has_backptr = True
        # impact-first survivor: unguarded path to the impact sink AND an
        # unguarded backward entrypoint reaching it.
        if rec.get("unguarded") is not True:
            continue
        if not _has_unguarded_entrypoint(rec):
            continue
        key = (str(sink.get("file", "")), sink.get("line", 0), kind)
        prev = by_site.get(key)
        if prev is None or _TIER_RANK[tier] > _TIER_RANK[prev["_tier"]]:
            by_site[key] = {
                "schema": SCHEMA,
                "novelty": "IMPACT-FIRST-BACKWARD",
                "verdict": "needs-search",
                "proof_status": "open",
                "attack_class": "impact-first-unguarded-reach",
                "impact_tier": tier,
                "_tier": tier,
                "impact_sink": {"kind": kind, "file": sink.get("file", ""),
                                "line": sink.get("line", 0)},
                "backward_entrypoints_total": rec.get("backward_entrypoints_total"),
                "backward_entrypoints_guarded": rec.get("backward_entrypoints_guarded"),
                "source": rec.get("source") or {},
                "direction_ambiguous": kind in _DIRECTION_AMBIGUOUS,
                "search_question": (
                    f"An UNGUARDED path reaches the {tier}-impact sink '{kind}' at "
                    f"{sink.get('file','')}:{sink.get('line',0)} AND >=1 backward "
                    f"entrypoint reaches it without a dominating guard "
                    f"({rec.get('backward_entrypoints_total')} total, "
                    f"{rec.get('backward_entrypoints_guarded')} guarded). Find the "
                    f"unprivileged entrypoint + confirm no compensating guard "
                    f"elsewhere, or REFUTE with the guard that dominates every entry."
                    + (" DIRECTION CHECK (mandatory): confirm the transfer's FROM "
                       "party is the PROTOCOL or ANOTHER user (real value-out / "
                       "drain); if FROM == msg.sender (caller moving their OWN funds, "
                       "e.g. safeTransferFrom(msg.sender, ...) in a deposit), this is "
                       "self-authorized and BENIGN -> REFUTE."
                       if kind in _DIRECTION_AMBIGUOUS else "")),
            }
    obligations = sorted(by_site.values(),
                         key=lambda o: -_TIER_RANK[o["_tier"]])
    for o in obligations:
        o.pop("_tier", None)
    tiers = defaultdict(int)
    for o in obligations:
        tiers[o["impact_tier"]] += 1
    return {
        "schema": SCHEMA,
        "workspace": str(ws),
        "paths_scanned": len(paths),
        "impact_sink_kinds": sorted(_IMPACT_TIER),
        "substrate_has_backward_entrypoints": substrate_has_backptr,
        "obligations": obligations,
        "obligation_count": len(obligations),
        "by_tier": dict(tiers),
        "status": "candidates" if obligations else (
            "cited_empty" if substrate_has_backptr else "substrate_missing_backptr"),
    }


def emit(ws: pathlib.Path, rep: dict) -> int:
    out = _adir(ws) / "impact_backward_obligations.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as fh:
        for o in rep["obligations"]:
            fh.write(json.dumps(o) + "\n")
    return len(rep["obligations"])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-emit", action="store_true")
    args = ap.parse_args(argv)
    ws = pathlib.Path(args.workspace).resolve()
    rep = analyse(ws)
    if not args.no_emit:
        emit(ws, rep)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"impact-first-backward-search: status={rep['status']} "
              f"paths={rep['paths_scanned']} obligations={rep['obligation_count']} "
              f"by_tier={rep['by_tier']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
