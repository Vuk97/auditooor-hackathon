#!/usr/bin/env python3
"""
detector-composer.py — Kimi 20/10 Step 3b.

Filters detector-hit JSON output by reading the workspace's callgraph
(`<workspace>/ccia/callgraph.json`, produced by
`tools/ccia.py --emit-callgraph` in PR #196 / Step 3a) and the precedence
rules in `reference/detector_precedence_rules.json`.

What it does

  - For each hit categorized A-RACE between two named contracts:
    drop the hit if the callgraph proves the two contracts share ZERO
    state-var names (the I-20 "name-collision but no proven mutable
    state" signal Kimi K11 named).

  - For each hit categorized A-AUTH between two named contracts:
    demote to "info" if the callgraph has no edge connecting the two
    contracts within 2 hops.

  - For each hit categorized A-ORACLE with a callsite contract:
    demote to "info" if the callsite is not within 2 hops of any node
    whose contract or function name matches a pricer/oracle heuristic.

  - Every other hit (uncategorized, no rule match, or constraint
    unprovable) is kept verbatim. Demotion requires affirmative
    evidence in the callgraph.

Hit input schema

  Each hit is a JSON object with at least these fields:
    {
      "detector": "<detector argument>",       // required
      "category": "A-RACE",                    // required for filtering
      "title": "...",                          // optional
      "description": "...",                    // optional
      "contracts": ["Foo", "Bar"],             // required for cross-contract rules
      "callsite": "Foo.transfer()",            // optional, used by A-ORACLE
      "severity": "high",                      // optional, written into output
    }

  Reads of detector hit JSON from `--hits` accept either:
    1. A bare list of hit objects, or
    2. A dict shaped {"results": [...], "hits": [...], "findings": [...]}
       (any of those keys is recognized — covers run_custom.py-style
       outputs and human-curated lists).

Output

  By default writes filtered hits to <workspace>/composed_hits.json with
  the schema:
    {
      "schema": "auditooor.detector-composer.v1",
      "input_count": N,
      "kept_count": K,
      "dropped_count": D,
      "demoted_count": M,
      "kept": [hit, ...],
      "actions": [
        {"action": "drop|demote_info|keep",
         "rule_id": "...", "reason": "...", "hit": {...}}, ...
      ]
    }

Usage

  python3 tools/detector-composer.py \
      --workspace <ws> \
      --hits <hits.json> \
      [--rules reference/detector_precedence_rules.json] \
      [--out <ws>/composed_hits.json]
  python3 tools/detector-composer.py --workspace <ws> --hits <hits.json> --print

Exit codes

  0 — composed successfully (regardless of whether anything was dropped)
  1 — invalid input (missing workspace / hits / callgraph)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

REPO = Path(__file__).resolve().parents[1]
DEFAULT_RULES = REPO / "reference" / "detector_precedence_rules.json"


# ─────────────────────────────────────────────────────────────────────
# Loading
# ─────────────────────────────────────────────────────────────────────


def load_callgraph(workspace: Path) -> Optional[Dict[str, Any]]:
    """Load <workspace>/ccia/callgraph.json. Returns None if missing —
    composer is conservative when the callgraph is absent (keeps all
    hits)."""
    cg_path = workspace / "ccia" / "callgraph.json"
    if not cg_path.is_file():
        return None
    try:
        return json.loads(cg_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"[composer] warning: callgraph at {cg_path} is invalid JSON: {e}",
              file=sys.stderr)
        return None


def load_rules(rules_path: Path) -> Dict[str, Any]:
    """Load the precedence rules file."""
    if not rules_path.is_file():
        raise SystemExit(f"[composer] rules file not found: {rules_path}")
    return json.loads(rules_path.read_text(encoding="utf-8"))


def load_hits(hits_path: Path) -> List[Dict[str, Any]]:
    """Load detector hits. Accepts a bare list, or a dict with one of
    `results` / `hits` / `findings`."""
    if not hits_path.is_file():
        raise SystemExit(f"[composer] hits file not found: {hits_path}")
    data = json.loads(hits_path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("results", "hits", "findings"):
            if isinstance(data.get(key), list):
                return data[key]
    raise SystemExit(
        f"[composer] hits file {hits_path} is neither a list nor a dict "
        f"with a 'results'/'hits'/'findings' list"
    )


# ─────────────────────────────────────────────────────────────────────
# Callgraph helpers
# ─────────────────────────────────────────────────────────────────────


def _contract_storage(callgraph: Dict[str, Any]) -> Dict[str, Set[str]]:
    raw = callgraph.get("contract_storage") or {}
    return {k: set(v or []) for k, v in raw.items()}


def _node_index(callgraph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {n["id"]: n for n in callgraph.get("nodes", []) if "id" in n}


def _adjacency(callgraph: Dict[str, Any]) -> Dict[str, List[str]]:
    """Return undirected adjacency for hop-count reachability checks
    (A-AUTH and A-ORACLE rules treat reachability as symmetric)."""
    adj: Dict[str, List[str]] = defaultdict(list)
    for e in callgraph.get("edges", []):
        s, d = e.get("src"), e.get("dst")
        if not s or not d:
            continue
        adj[s].append(d)
        adj[d].append(s)
    return adj


def _bfs_within(adj: Dict[str, List[str]], start: str, max_hops: int) -> Set[str]:
    """BFS from `start` up to `max_hops` edges. Returns the set of
    visited node ids (incl. start)."""
    seen = {start}
    frontier = deque([(start, 0)])
    while frontier:
        node, depth = frontier.popleft()
        if depth >= max_hops:
            continue
        for nxt in adj.get(node, []):
            if nxt in seen:
                continue
            seen.add(nxt)
            frontier.append((nxt, depth + 1))
    return seen


def _contract_of(node_id: str) -> str:
    """`Contract.fn()` -> `Contract`. `Contract` -> `Contract`."""
    if "." in node_id:
        return node_id.split(".", 1)[0]
    return node_id


# ─────────────────────────────────────────────────────────────────────
# Rule application
# ─────────────────────────────────────────────────────────────────────


def _normalize_demotion(raw: str) -> str:
    """Map the rules-file `demotion` token to the composer's internal
    action vocabulary. The rules file uses operator-friendly names
    (`drop`, `info`); compose() / _apply_rule keys on stable strings."""
    if raw == "drop":
        return "drop"
    if raw in ("info", "demote_info"):
        return "demote_info"
    if raw == "keep":
        return "keep"
    # Unknown token — fail safe by keeping (matches the conservative
    # default the rules file documents).
    return "keep"


def _category_matches(hit_category: str, rule_match_list: List[str]) -> bool:
    if not hit_category:
        return False
    hc = hit_category.strip()
    for tag in rule_match_list:
        if tag.lower() == hc.lower():
            return True
        # Substring fallback for free-form categories like
        # "cross-contract-race / A-RACE".
        if tag.lower() in hc.lower():
            return True
    return False


def _find_rule(category: str, rules: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for rule in rules.get("rules", []):
        match_list = (rule.get("applies_when") or {}).get("category_match") or []
        if _category_matches(category, match_list):
            return rule
    return None


def _apply_a_race(
    hit: Dict[str, Any],
    rule: Dict[str, Any],
    contract_storage: Dict[str, Set[str]],
) -> Tuple[str, str]:
    """Returns (action, reason). action ∈ {"keep", "drop", "demote_info"}."""
    contracts = hit.get("contracts") or []
    if len(contracts) < 2:
        return "keep", "A-RACE rule requires two contracts in hit; insufficient data"
    a, b = contracts[0], contracts[1]
    sa = contract_storage.get(a)
    sb = contract_storage.get(b)
    # Conservative: if either contract is unknown to the callgraph,
    # we cannot disprove the brief — keep it.
    if sa is None or sb is None:
        return "keep", (
            f"A-RACE constraint unprovable: {a if sa is None else b} "
            f"not in callgraph contract_storage"
        )
    shared = sa & sb
    if shared:
        return "keep", f"A-RACE shared keys: {sorted(shared)}"
    template = rule.get("demotion_reason_template", "")
    reason = template.format(a=a, b=b) if template else (
        f"callgraph: contracts {a} and {b} share zero state-var names"
    )
    return _normalize_demotion(rule.get("demotion", "drop")), reason


def _apply_a_auth(
    hit: Dict[str, Any],
    rule: Dict[str, Any],
    callgraph: Dict[str, Any],
) -> Tuple[str, str]:
    contracts = hit.get("contracts") or []
    if len(contracts) < 2:
        return "keep", "A-AUTH rule requires two contracts in hit; insufficient data"
    a, b = contracts[0], contracts[1]
    nodes = _node_index(callgraph)
    contracts_in_graph = {n["contract"] for n in nodes.values() if "contract" in n}
    if a not in contracts_in_graph or b not in contracts_in_graph:
        return "keep", (
            f"A-AUTH constraint unprovable: "
            f"{a if a not in contracts_in_graph else b} not in callgraph nodes"
        )
    adj = _adjacency(callgraph)
    a_nodes = [nid for nid, n in nodes.items() if n.get("contract") == a]
    max_hops = int(rule.get("max_hops", 2))
    reachable_b = False
    for start in a_nodes:
        reach = _bfs_within(adj, start, max_hops)
        if any(nodes.get(r, {}).get("contract") == b for r in reach):
            reachable_b = True
            break
    if reachable_b:
        return "keep", f"A-AUTH reachable: {a} ↔ {b} within {max_hops} hops"
    template = rule.get("demotion_reason_template", "")
    reason = template.format(a=a, b=b) if template else (
        f"callgraph: no reachability edge between {a} and {b} within {max_hops} hops"
    )
    return _normalize_demotion(rule.get("demotion", "info")), reason


def _apply_a_oracle(
    hit: Dict[str, Any],
    rule: Dict[str, Any],
    callgraph: Dict[str, Any],
) -> Tuple[str, str]:
    callsite = hit.get("callsite")
    if not callsite:
        return "keep", "A-ORACLE rule requires callsite in hit; insufficient data"
    nodes = _node_index(callgraph)
    if callsite not in nodes:
        # Try resolving by contract prefix only (e.g. "Foo" -> any Foo node)
        prefix = callsite.split(".", 1)[0]
        candidates = [nid for nid, n in nodes.items()
                      if n.get("contract") == prefix]
        if not candidates:
            return "keep", f"A-ORACLE constraint unprovable: callsite {callsite} not in callgraph"
        callsite_nodes = candidates
    else:
        callsite_nodes = [callsite]
    adj = _adjacency(callgraph)
    max_hops = int(rule.get("max_hops", 2))
    pricer_terms = [t.lower() for t in rule.get("pricer_name_heuristics") or []]
    if not pricer_terms:
        return "keep", "A-ORACLE rule has empty pricer_name_heuristics; cannot evaluate"
    for start in callsite_nodes:
        reach = _bfs_within(adj, start, max_hops)
        for nid in reach:
            n = nodes.get(nid, {})
            cname = (n.get("contract") or "").lower()
            fname = (n.get("function") or "").lower()
            if any(t in cname or t in fname for t in pricer_terms):
                return "keep", f"A-ORACLE callsite {callsite} within {max_hops} hops of pricer node {nid}"
    template = rule.get("demotion_reason_template", "")
    reason = template.format(site=callsite) if template else (
        f"callgraph: callsite {callsite} is not within {max_hops} hops of any pricer/oracle node"
    )
    return _normalize_demotion(rule.get("demotion", "info")), reason


def _apply_rule(
    hit: Dict[str, Any],
    rule: Dict[str, Any],
    callgraph: Dict[str, Any],
    contract_storage: Dict[str, Set[str]],
) -> Tuple[str, str]:
    rule_id = rule.get("rule_id", "")
    if rule_id.startswith("A-RACE"):
        return _apply_a_race(hit, rule, contract_storage)
    if rule_id.startswith("A-AUTH"):
        return _apply_a_auth(hit, rule, callgraph)
    if rule_id.startswith("A-ORACLE"):
        return _apply_a_oracle(hit, rule, callgraph)
    return "keep", f"no handler for rule_id {rule_id}"


# ─────────────────────────────────────────────────────────────────────
# Top-level compose
# ─────────────────────────────────────────────────────────────────────


def compose(
    hits: List[Dict[str, Any]],
    callgraph: Optional[Dict[str, Any]],
    rules: Dict[str, Any],
) -> Dict[str, Any]:
    """Return the composed result: kept hits + per-hit actions."""
    actions: List[Dict[str, Any]] = []
    kept: List[Dict[str, Any]] = []
    drop_count = 0
    demote_count = 0

    contract_storage: Dict[str, Set[str]] = (
        _contract_storage(callgraph) if callgraph else {}
    )

    for hit in hits:
        category = (hit.get("category") or "").strip()
        rule = _find_rule(category, rules) if category else None
        if rule is None or callgraph is None:
            kept.append(hit)
            actions.append({
                "action": "keep",
                "rule_id": rule.get("rule_id") if rule else None,
                "reason": (
                    "no callgraph available — conservative keep"
                    if callgraph is None
                    else f"no precedence rule matched category {category!r}"
                ),
                "hit": hit,
            })
            continue

        action, reason = _apply_rule(hit, rule, callgraph, contract_storage)
        record = {
            "action": action,
            "rule_id": rule.get("rule_id"),
            "reason": reason,
            "hit": hit,
        }
        actions.append(record)
        if action == "keep":
            kept.append(hit)
        elif action == "demote_info":
            demote_count += 1
            demoted = dict(hit)
            demoted["severity"] = "info"
            demoted["composer_demoted_from"] = hit.get("severity")
            demoted["composer_reason"] = reason
            kept.append(demoted)
        elif action == "drop":
            drop_count += 1
        else:
            # Unknown action — fail safe by keeping
            kept.append(hit)

    return {
        "schema": "auditooor.detector-composer.v1",
        "input_count": len(hits),
        "kept_count": sum(1 for a in actions if a["action"] != "drop"),
        "dropped_count": drop_count,
        "demoted_count": demote_count,
        "kept": kept,
        "actions": actions,
    }


# ─────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compose detector hits using cross-contract callgraph "
                    "(Kimi 20/10 Step 3b)"
    )
    parser.add_argument("--workspace", required=True, type=Path,
                        help="Workspace directory (must contain ccia/callgraph.json)")
    parser.add_argument("--hits", required=True, type=Path,
                        help="JSON file with detector hits "
                             "(list, or dict with results/hits/findings key)")
    parser.add_argument("--rules", default=DEFAULT_RULES, type=Path,
                        help="Path to detector_precedence_rules.json")
    parser.add_argument("--out", default=None, type=Path,
                        help="Output path (default: <workspace>/composed_hits.json)")
    parser.add_argument("--print", action="store_true",
                        help="Print the composed JSON to stdout")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress info banner")
    args = parser.parse_args(argv)

    workspace = args.workspace.resolve()
    hits = load_hits(args.hits)
    rules = load_rules(args.rules)
    callgraph = load_callgraph(workspace)

    if callgraph is None and not args.quiet:
        print(
            f"[composer] info: no callgraph at {workspace}/ccia/callgraph.json — "
            f"all {len(hits)} hits kept (conservative). "
            f"Run `tools/ccia.py {workspace} --emit-callgraph` first to enable "
            f"the precedence rules.",
            file=sys.stderr,
        )

    result = compose(hits, callgraph, rules)

    out_path = args.out or (workspace / "composed_hits.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    if not args.quiet:
        print(
            f"[composer] input={result['input_count']} "
            f"kept={result['kept_count']} "
            f"dropped={result['dropped_count']} "
            f"demoted={result['demoted_count']} "
            f"-> {out_path}"
        )

    if args.print:
        print(json.dumps(result, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
