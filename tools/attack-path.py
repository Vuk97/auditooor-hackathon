#!/usr/bin/env python3
"""
attack-path.py — R76 A: reachability + attack-flow analyzer.

Top auditors don't just look at individual functions. They trace EVERY
external entry point to every high-value SINK (token transfer, storage
write that changes access, ETH send, mint/burn, upgrade).  For each
path, they ask: "what guards protect the sink, and can any of them be
bypassed from the entry point?"

This tool automates that reasoning at the AST level using Slither's
call graph and CFG.

Output: <workspace>/attack_paths.md — a ranked list of (entry → sink)
paths with:
  - entry point (external function, contract name)
  - sink (function.state-write / external call / transfer)
  - guard chain (modifiers + require/assert between entry and sink)
  - bypass hypotheses (which guards rely on caller-controlled input)

Usage:
  python3 tools/attack-path.py <workspace>
  python3 tools/attack-path.py <workspace> --contract LendingPool
  python3 tools/attack-path.py <workspace> --sink-type transfer|mint|upgrade|auth

Each path gets a severity score based on:
  - Sink value (CRITICAL for upgrade+mint, HIGH for transfer+auth-change, MEDIUM for fee/reward)
  - Guard depth (fewer guards = higher score)
  - Caller-controlled preconditions (attacker-controlled = higher score)
"""

import argparse
import json
import pathlib
import sys
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _analyzer_common import iter_source_files

# Shared, cycle-guarded, UNBOUNDED-depth call-graph closure primitive. The
# bounded BFS below (`_reachable_functions`) now delegates its UNBOUNDED case
# to this so the two tools share one cycle-guard implementation.
try:
    from slither_predicates import callee_closure as _callee_closure, is_degraded as _is_degraded
except Exception:  # pragma: no cover - defensive, slither_predicates is local
    _callee_closure = None
    _is_degraded = None

try:
    from slither.slither import Slither
except ImportError:
    print("[err] Slither not installed. pip install slither-analyzer", file=sys.stderr)
    sys.exit(1)


# ── Sink classification — what constitutes a "high-value effect" ──
SINK_WEIGHTS = {
    "upgrade": 100,           # proxy upgrade / selfdestruct
    "auth_change": 80,        # grantRole, transferOwnership, setAdmin
    "mint_burn": 75,          # token mint / burn
    "eth_send": 70,           # call{value}, transfer, selfdestruct
    "token_transfer": 60,     # ERC20 transfer / transferFrom
    "state_write_critical": 50,  # writes to fee / rate / oracle / pauser vars
    "reward_distribute": 40,  # reward claim / distribute
    "state_write_other": 20,  # generic state mutation
    "external_call": 15,      # any external call
}

SINK_KEYWORDS = {
    "upgrade": ["upgradeTo", "_setImplementation", "selfdestruct", "SELFDESTRUCT"],
    "auth_change": ["grantRole", "revokeRole", "transferOwnership", "_setOwner",
                    "setAdmin", "setOwner", "acceptOwnership", "_grantRole"],
    "mint_burn": ["_mint", "_burn", "mint", "burn"],
    "eth_send": ["sendValue", "transfer", "send", ".call{value"],
    "token_transfer": ["safeTransfer", "safeTransferFrom", "transferFrom", "transfer"],
    "state_write_critical": ["fee", "rate", "pause", "oracle", "threshold", "limit"],
    "reward_distribute": ["distributeReward", "claimReward", "harvest", "compound"],
}


def _function_source(fn):
    try:
        return fn.source_mapping.content or ""
    except Exception:
        return ""


def _classify_sink(node, function):
    """Classify a single CFG node as a sink type (or return None)."""
    # 1. External / high-level calls
    hl = list(getattr(node, "high_level_calls", []) or [])
    ll = list(getattr(node, "low_level_calls", []) or [])

    expr = str(getattr(node, "expression", "") or "")

    for call in hl:
        fn_obj = call[1] if isinstance(call, (list, tuple)) and len(call) >= 2 else call
        name = getattr(fn_obj, "name", "") or ""
        for sink_type, keywords in SINK_KEYWORDS.items():
            for kw in keywords:
                if kw in name:
                    return sink_type, name
    for _lc in ll:
        if "call{value" in expr or ".value(" in expr or "sendValue" in expr:
            return "eth_send", "low_level_call_with_value"
        if "delegatecall" in expr:
            return "upgrade", "delegatecall"
    # 2. State-writes: check what's being written
    writes = list(getattr(node, "state_variables_written", []) or [])
    for sv in writes:
        nm = (getattr(sv, "name", "") or "").lower()
        for critical_kw in SINK_KEYWORDS["state_write_critical"]:
            if critical_kw in nm:
                return "state_write_critical", f"write({sv.name})"
    if writes:
        return "state_write_other", f"write({writes[0].name})"
    return None


def _collect_guards(function):
    """Walk modifiers + require/assert calls in the function body. Return
    a tuple (modifier_names, require_exprs)."""
    mods = [getattr(m, "name", "") or "?" for m in (getattr(function, "modifiers", []) or [])]
    requires = []
    for node in getattr(function, "nodes", []) or []:
        expr = str(getattr(node, "expression", "") or "")
        if expr.startswith("require(") or expr.startswith("assert(") or "revert" in expr.split("(", 1)[0]:
            requires.append(expr[:120])
    return mods, requires


def _entry_points(contract):
    """External / public functions on the contract — potential attack entry
    points (excluding view/pure)."""
    out = []
    for fn in getattr(contract, "functions_and_modifiers_declared", []) or []:
        if getattr(fn, "visibility", "") not in ("external", "public"):
            continue
        if getattr(fn, "view", False) or getattr(fn, "pure", False):
            continue
        if getattr(fn, "is_constructor", False):
            continue
        out.append(fn)
    return out


def _reachable_functions(entry_fn, max_depth=5):
    """Return the set of functions reachable from entry_fn via internal
    or high-level calls.

    When ``max_depth`` is None (or <= 0) this delegates to the shared
    UNBOUNDED, cycle-guarded ``slither_predicates.callee_closure`` primitive
    (the new substrate; modifier bodies excluded here to preserve attack-path's
    historical call-edge-only semantics). When ``max_depth`` is a positive int
    the original bounded BFS is preserved verbatim so attack-path's existing
    depth-4 call behaves exactly as before."""
    if (max_depth is None or max_depth <= 0) and _callee_closure is not None:
        closure = _callee_closure(entry_fn, include_modifiers=False)
        if _is_degraded is not None and _is_degraded(closure):
            return {entry_fn}
        result = set(closure)
        result.add(entry_fn)
        return result

    seen = {entry_fn}
    frontier = [entry_fn]
    depth = 0
    while frontier and depth < max_depth:
        next_frontier = []
        for fn in frontier:
            for node in getattr(fn, "nodes", []) or []:
                # Internal calls
                for ic in (getattr(node, "internal_calls", []) or []):
                    if hasattr(ic, "nodes") and ic not in seen:
                        seen.add(ic); next_frontier.append(ic)
                # High-level calls (call graph edges)
                for call in (getattr(node, "high_level_calls", []) or []):
                    fn_obj = call[1] if isinstance(call, (list, tuple)) and len(call) >= 2 else call
                    if hasattr(fn_obj, "nodes") and fn_obj not in seen:
                        seen.add(fn_obj); next_frontier.append(fn_obj)
        frontier = next_frontier
        depth += 1
    return seen


def _analyze_workspace(ws, only_contract=None, only_sink_type=None):
    paths = []
    # Find Solidity sources under the workspace
    for sol_file in iter_source_files(ws, max_files=200):  # R79 T3: shared skip-paths
        try:
            slither = Slither(str(sol_file))
        except Exception as e:
            continue
        for contract in slither.contracts:
            if only_contract and contract.name != only_contract:
                continue
            if contract.is_interface or contract.is_library:
                continue
            for entry in _entry_points(contract):
                reach = _reachable_functions(entry, max_depth=4)
                for fn in reach:
                    for node in getattr(fn, "nodes", []) or []:
                        cls = _classify_sink(node, fn)
                        if cls is None:
                            continue
                        sink_type, sink_name = cls
                        if only_sink_type and sink_type != only_sink_type:
                            continue
                        mods, requires = _collect_guards(entry)
                        paths.append({
                            "entry_contract": contract.name,
                            "entry_fn": entry.name,
                            "sink_fn": fn.name,
                            "sink_type": sink_type,
                            "sink_name": sink_name,
                            "guards_mods": mods,
                            "guards_requires": requires,
                            "weight": SINK_WEIGHTS.get(sink_type, 0),
                            "guard_depth": len(mods) + len(requires),
                            "file": str(sol_file),
                        })
    return paths


def _score_path(p):
    """Attacker-favored score: high sink weight, low guard depth."""
    w = p["weight"]
    g = max(p["guard_depth"], 1)
    # Adjust: if the only guard is `onlyOwner` or similar, assume admin-gated (lower threat)
    admin_gates = {"onlyOwner", "onlyAdmin", "onlyGovernance", "onlyRole"}
    if any(m in admin_gates for m in p["guards_mods"]):
        return w // 3  # Admin-gated paths are lower attacker-reachable threat
    return w // g


def _render_report(paths, out_path):
    paths.sort(key=_score_path, reverse=True)
    with open(out_path, "w") as f:
        f.write("# Attack-path analyzer report\n\n")
        f.write(f"Generated by `tools/attack-path.py`. Paths sorted by "
                f"(sink weight ÷ guard depth, admin-gated reduced).\n\n")
        f.write(f"**{len(paths)} reachable (entry → sink) paths** across the workspace.\n\n")

        # Group by entry contract
        by_contract = defaultdict(list)
        for p in paths:
            by_contract[p["entry_contract"]].append(p)

        for cname in sorted(by_contract.keys()):
            entries = by_contract[cname]
            f.write(f"\n## Contract: `{cname}` — {len(entries)} paths\n\n")
            f.write("| Rank | Entry fn | Sink fn | Sink type | Sink name | Guards | Score |\n")
            f.write("|---:|---|---|---|---|---|---:|\n")
            for i, p in enumerate(sorted(entries, key=_score_path, reverse=True), 1):
                guards = ", ".join(p["guards_mods"]) or "—"
                if not p["guards_mods"] and not p["guards_requires"]:
                    guards = "**NONE**"
                elif p["guards_requires"] and not p["guards_mods"]:
                    guards = f"({len(p['guards_requires'])} require)"
                score = _score_path(p)
                f.write(f"| {i} | `{p['entry_fn']}` | `{p['sink_fn']}` | "
                        f"{p['sink_type']} | `{p['sink_name']}` | {guards} | {score} |\n")

        f.write("\n## Methodology\n\n")
        f.write("For every external/public entry point:\n\n")
        f.write("1. Compute the call-graph-reachable set (depth ≤ 4) via internal + high-level calls.\n")
        f.write("2. In each reachable function, identify sink nodes (upgrade / mint / transfer / auth-change / state-write).\n")
        f.write("3. Collect guards at the ENTRY point (modifiers + requires).\n")
        f.write("4. Score = sink_weight ÷ guard_depth, with admin-gated paths penalized (admin compromise is a separate threat model).\n\n")
        f.write("**Top-ranked paths are where a low-privileged caller can reach a high-value sink with few guards. Review them first.**\n")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("workspace")
    ap.add_argument("--contract", default=None)
    ap.add_argument("--sink-type", default=None, choices=list(SINK_WEIGHTS.keys()))
    ap.add_argument("--top", type=int, default=50)
    args = ap.parse_args()
    ws = pathlib.Path(args.workspace)
    if not ws.is_dir():
        print(f"[err] workspace not found: {ws}", file=sys.stderr); sys.exit(1)
    paths = _analyze_workspace(ws, args.contract, args.sink_type)
    if not paths:
        print("[info] no paths found — check workspace has src/*.sol files", file=sys.stderr)
        sys.exit(0)
    out = ws / "attack_paths.md"
    _render_report(paths, out)
    print(f"[ok] wrote {out} ({len(paths)} paths)")
    print(f"     top 5 by score:")
    for p in sorted(paths, key=_score_path, reverse=True)[:5]:
        print(f"       {_score_path(p):4d}  {p['entry_contract']}.{p['entry_fn']} → {p['sink_fn']} [{p['sink_type']}]")

if __name__ == "__main__":
    main()
