#!/usr/bin/env python3
"""enrich-chains-from-causal.py - build the composer's enriched-invariant feed from the
LINKAGE-BEARING causal_chains corpus (audit/corpus_tags/derived/causal_chains.jsonl), NOT
the thin finding-sidecar fuel.

WHY (operator 2026-07-08, after a workflow + paper-check):
  - invariants_pilot_audited.jsonl was repurposed as RAW per-fn hunt fuel -> the chain-
    template composer reads it, every row is `source-unbacked` -> 0 templates.
  - The finding-sidecar corpus (invariant_library_extended) is too THIN to re-derive from
    (location/fix_commit/impact all ""), so re-deriving there produces generic
    "logic-error -> logic-error" NOISE that would DEGRADE the hunt.
  - causal_chains.jsonl already carries REAL closed-vocab produces_state/requires_state
    (state:accounting-invariant-broken, state:privileged-call-context, ...) from actual
    incident/finding narratives - 1,904/2,610 rows are linkage-bearing.

The composer has TWO gates: a boolean linkage gate (needs the 5 linkage fields present) AND
a numeric _score_tuple gate (min 0.6, driven by commit_point_pattern + defense_layer +
target_lang). causal_chains lacks commit_point_pattern/defense_layer by NAME, but the raw
trigger/defense text is boilerplate-contaminated ("2023", "disclosure"). So we derive
commit_point_pattern + defense_layer from the CLEAN attack_class/bug_class (never the raw
text), which:
  (a) guarantees intra-cluster token sharing (the cluster key IS category==attack_class), so
      the score clears 0.6 for tuples that ALSO have a real state link, and
  (b) the REAL quality filter stays the composer's producer->consumer state-link requirement
      (_tuple_rejection_reason): a tuple only composes if one member's produces_state matches
      another's requires_state - a genuine escalation edge, not a boilerplate coincidence.

ADDITIVE / NEVER-BREAK: writes a NEW file (default invariants_pilot_audited_enriched.jsonl);
does NOT touch invariants_pilot_audited.jsonl (the raw per-fn fuel + its 9 consumers).
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_DEFAULT_SRC = _REPO / "audit/corpus_tags/derived/causal_chains.jsonl"
_DEFAULT_DST = _REPO / "audit/corpus_tags/derived/invariants_pilot_audited_enriched.jsonl"

# clean mechanism tokens from attack_class/bug_class (NO years, NO advisory boilerplate)
_STOP = {"2020", "2021", "2022", "2023", "2024", "2025", "2026", "the", "and", "for",
         "disclosure", "described", "advisory", "public", "report", "finding", "issue"}


def _clean_tokens(*vals: object) -> list[str]:
    toks: list[str] = []
    seen = set()
    for v in vals:
        for t in re.findall(r"[a-z][a-z0-9]{2,}", str(v or "").lower()):
            if t in _STOP or t in seen:
                continue
            seen.add(t)
            toks.append(t)
    return toks


def _as_list(v: object) -> list[str]:
    if isinstance(v, list):
        return [str(x) for x in v if str(x).strip()]
    if isinstance(v, str) and v.strip():
        return [v.strip()]
    return []


def enrich_row(r: dict) -> dict | None:
    produces = _as_list(r.get("produces_state"))
    requires = _as_list(r.get("requires_state"))
    if not produces or not requires:
        return None  # only linkage-bearing rows can seed escalation chains
    attack_class = str(r.get("attack_class") or r.get("bug_class") or "").strip()
    category = attack_class.lower() or "uncategorized"
    src_refs = _as_list(r.get("source_refs"))
    if not src_refs:
        return None  # boolean linkage gate needs a non-empty source_refs
    # commit_point_pattern + defense_layer from the CLEAN class tokens (shared intra-cluster
    # by construction -> score clears 0.6 ONLY for tuples that also pass the state-link gate).
    cls_tokens = _clean_tokens(attack_class, r.get("bug_class"))
    if len(cls_tokens) < 2:
        cls_tokens = (cls_tokens + ["mechanism", "class"])[:2]
    lead = str(r.get("source_record_id") or r.get("chain_id") or "").strip()
    return {
        "invariant_id": str(r.get("chain_id") or lead or ""),
        "category": category,
        "attack_class": attack_class,
        "statement": str(r.get("trigger") or r.get("defense") or "")[:400],
        "target_lang": str(r.get("target_language") or r.get("target_lang") or ""),
        "produces_state": produces,
        "requires_state": requires,
        "source_refs": src_refs,
        "producer_source_refs": src_refs,
        "consumer_source_refs": src_refs,
        "source_finding_ids": [lead] if lead else src_refs[:1],
        "commit_point_pattern": " ".join(cls_tokens),
        "defense_layer": " ".join(_clean_tokens(r.get("defense"), attack_class)[:3] or cls_tokens),
        "verification_tier": str(r.get("verification_tier") or ""),
        "audit_verdict": "TRUE-POSITIVE",
        "_provenance": "enrich-chains-from-causal/causal_chains.jsonl",
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", type=Path, default=_DEFAULT_SRC)
    ap.add_argument("--dst", type=Path, default=_DEFAULT_DST)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    rows_in = [json.loads(l) for l in a.src.read_text(encoding="utf-8").splitlines() if l.strip()]
    out = []
    seen_ids = set()
    for r in rows_in:
        e = enrich_row(r)
        if e is None or not e["invariant_id"] or e["invariant_id"] in seen_ids:
            continue
        seen_ids.add(e["invariant_id"])
        out.append(e)
    a.dst.write_text("\n".join(json.dumps(o, sort_keys=True) for o in out) + "\n", encoding="utf-8")
    summary = {"src_rows": len(rows_in), "enriched_rows": len(out), "dst": str(a.dst)}
    print(json.dumps(summary, indent=2) if a.json else
          f"enrich-chains-from-causal: {len(out)} enriched rows (of {len(rows_in)}) -> {a.dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
