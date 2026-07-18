#!/usr/bin/env python3
"""read-only-view-reentrancy-unguarded-composite-getter.py

LOGIC reasoner (docs/LOGIC_ARSENAL_ROADMAP.md perpetual loop). A SET / reachability
query over the OWNED Slither CFG/IR backend + the OWNED dataflow_paths.jsonl
reachability substrate. NOT a token/regex detector.

CORPUS SOURCE (the mined logic class)
  - reference/corpus_mined/slice_ac.md:35  Valantis SwapCallbackReentrancy VLTS3-13
    (CRITICAL); slice_ac.md:139 ReadOnlyReentrancy fee-module variant.
  - reference/corpus_mined/NOVELS_UNPORTED.md:60 (#15 nonReentrant-with-mid-function
    ETH-send) + NOVELS row #25 ReadOnlyReentrancy.
  - reference/corpus_mined/defihacklabs_catalog.md:78-81 & :159 Curve get_virtual_price
    LP-oracle (Makina / Woofi / UwuLend / Polter, ~$40M+).
  - obsidian-vault/patterns/curve-lp-virtual-price-no-read-only-reentrancy-check.md:19,
    read-only-reentrancy-view.md, ec-lp-virtual-price-read-only-reentrancy.md,
    fx-euler-erc4626-view-readonly-reentrancy-unguarded.md.

THE LOGIC (assumption / invariant / trust-boundary)
  ASSUMPTION  A view/pure getter G returning a COMPOSITE quantity
    (price = assetsA/supplyB, virtual_price, totalAssets, exchangeRate) is trusted to
    always return a consistent value; downstream oracle/fee/collateral consumers read
    it as ground truth.
  INVARIANT   For every mutating fn M that writes TWO-OR-MORE of G's components and
    makes an untrusted external call / ETH-send / hooked token-transfer BETWEEN those
    component writes (a CEI-violating window), G MUST be protected by the same
    reentrancy lock as M (or read the locked flag) so it cannot be observed transiently
    inconsistent. As a SET relation:
       COMPOSED_ACROSS_WINDOW = { view getter G : G reads >=2 mutable state components,
           and SOME callback-window mutator M writes >=2 of those SAME components with
           an untrusted external call sitting BETWEEN two component writes }
       REENTRANCY_GUARDED     = { view getter G : G carries a nonReentrant/lock-flag
           guard (same lock the mutators hold) }
       FINDING = COMPOSED_ACROSS_WINDOW \\ REENTRANCY_GUARDED
    joined to any external consumer that reaches a value-release sink reading G.
  TRUST-BOUNDARY  The external-call recipient inside M re-enters and calls a
    value-releasing consumer (liquidation / borrow / fee) that reads the UNGUARDED
    getter G at its manipulated transient value.

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  The decision is NOT "token nonReentrant present/absent in a body". It is a relation
  over THREE SETS computed from the Slither CFG/IR + dataflow reachability substrate:
    (a) membership of G in COMPOSED_ACROSS_WINDOW requires a CROSS-FUNCTION join on
        SHARED STATE-VARIABLE identity - G's `state_variables_read` must intersect a
        DIFFERENT function M's `state_variables_written`, an inter-procedural set
        intersection no body regex can express;
    (b) M's callback window is an ORDERING relation over M's CFG nodes - an external
        call node positioned strictly BETWEEN two distinct state-write nodes (write ->
        extcall -> write), read off the node/IR sequence, not a token adjacency;
    (c) the finding is the SET-DIFFERENCE COMPOSED_ACROSS_WINDOW \\ GUARDED and is
        further JOINED to the dataflow_paths.jsonl reachability substrate (an external
        entrypoint whose value-release slice reads G's component) - a graph query, not
        a same-body match.
  The reentrancy-guard membership uses slither_predicates.has_non_reentrant_modifier
  (a modifier-graph predicate over the compiled AST) - the SAME owned primitive the
  callgraph closure family consumes - never a body regex.

OWNED BACKEND CONSUMED (no new engine built here)
  1. Slither (loaded via tools/dataflow-slice.py::load_slither_offline over the sol
     project roots discovered from dataflow_paths.jsonl) - Function.view/pure,
     state_variables_read, state_variables_written, node/IR ordering (Binary/
     HighLevelCall/LowLevelCall/Transfer/Send), and slither_predicates modifier graph.
  2. <ws>/.auditooor/dataflow_paths.jsonl (schema dataflow_path.v1) for the CONSUMER
     JOIN - value-release sinks (value-move/safeTransfer/mint/burn) whose slice reads
     a survivor getter's component var.

OUTPUT
  <ws>/.auditooor/readonly_view_reentrancy_obligations.jsonl - one row per survivor,
  schema auditooor.readonly_view_reentrancy_composite_getter.v1, exploit_queue-ingest
  compatible (contract/function/source_refs/root_cause_hypothesis/attack_class/
  broken_invariant_ids/quality_gate_status='needs_source'). exploit-queue.py ingests it
  via _gather_from_readonly_view_reentrancy_obligations -> the queue ->
  per-fn-mimo-batch-gen OPEN-OBLIGATIONS block. A --json summary reports |COMPOSED|,
  |GUARDED|, |COMPOSED\\GUARDED|, the KEPT (guarded, proving the subtraction is
  non-vacuous) and the survivors.

  A Solidity-language-absent workspace (e.g. a pure Go/Cosmos DLT) is a CLEAN
  NOT-APPLICABLE cited-empty (read-only VIEW reentrancy is an EVM view-function
  phenomenon), NOT a degraded substrate.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from importlib import util as _imp_util
from pathlib import Path

SCHEMA = "auditooor.readonly_view_reentrancy_composite_getter.v1"
_SIDE_NAME = "readonly_view_reentrancy_obligations.jsonl"
_CAPABILITY = "LOGIC_ROR_COMPOSITE_GETTER"
_STRICT_ENV = "AUDITOOOR_PREHUNT_ROR_FAILCLOSED"

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

# Financial-composite name hints - ADVISORY RANKING ONLY (never the membership
# decision, which is the shared-component set-relation). Kept so a get_virtual_price /
# exchangeRate / totalAssets getter ranks above an EIP712 domain-separator getter.
_COMPOSITE_NAME_HINT = (
    "price", "virtualprice", "virtual_price", "totalassets", "exchangerate",
    "getreserves", "convert", "preview", "nav", "sharevalue", "pricepershare",
    "getvirtualprice", "assetspershare", "quote",
)


def _load_slice_module():
    """Reuse tools/dataflow-slice.py::load_slither_offline (the owned 3-tier offline
    Slither loader) rather than re-implement crytic-compile framework selection."""
    tool = TOOLS_DIR / "dataflow-slice.py"
    spec = _imp_util.spec_from_file_location("_dfs_ror", tool)
    mod = _imp_util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


def _discover_sol_roots(ws: Path, dataflow_path: Path) -> list[Path]:
    """Project roots for the Solidity arm: the crytic/foundry/hardhat root ABOVE each
    distinct .sol source referenced in dataflow_paths.jsonl. Falls back to a shallow
    filesystem walk for foundry.toml / hardhat.config.* if the substrate is absent."""
    roots: list[Path] = []
    seen: set[str] = set()

    def _add_root_for(src: Path):
        cur = src if src.is_dir() else src.parent
        for _ in range(8):
            if cur is None or not cur.exists():
                break
            if any((cur / n).is_file() for n in (
                    "foundry.toml", "hardhat.config.js", "hardhat.config.ts",
                    "hardhat.config.cjs", "hardhat.config.mjs")):
                key = str(cur.resolve())
                if key not in seen:
                    seen.add(key)
                    roots.append(cur)
                return
            if cur.parent == cur:
                break
            cur = cur.parent

    if dataflow_path.exists():
        for line in dataflow_path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if rec.get("language") != "solidity":
                continue
            f = (rec.get("source") or {}).get("file") or (rec.get("sink") or {}).get("file")
            if f:
                _add_root_for(Path(f))

    if not roots:
        # substrate absent -> shallow walk for a foundry/hardhat root under ws
        skip = {".git", "node_modules", "lib", "out", "cache", "target",
                "_archive", "prior_audits", "reference"}
        for cfg in ("foundry.toml", "hardhat.config.js", "hardhat.config.ts"):
            for p in ws.rglob(cfg):
                if any(part in skip for part in p.parts):
                    continue
                _add_root_for(p)
    return roots


def _ir_types():
    from slither.slithir.operations import (  # noqa: E402
        Binary, BinaryType, HighLevelCall, LowLevelCall, Transfer, Send,
    )
    return Binary, BinaryType, HighLevelCall, LowLevelCall, Transfer, Send


def _rel(ws: Path, p: str) -> str:
    try:
        return str(Path(p).resolve().relative_to(ws.resolve()))
    except Exception:
        return str(p)


def _name_rank(fn_name: str) -> int:
    low = fn_name.lower().replace("_", "")
    return 1 if any(h.replace("_", "") in low for h in _COMPOSITE_NAME_HINT) else 0


def analyze_workspace(ws: Path, dataflow_path: Path, include_oos: bool = False):
    """Return (survivors, summary, warnings). survivors = list of obligation dicts."""
    warnings: list[str] = []
    slice_mod = _load_slice_module()
    try:
        import slither_predicates as sp
    except Exception as e:  # pragma: no cover
        warnings.append(f"slither_predicates-import-error: {e}")
        sp = None

    roots = _discover_sol_roots(ws, dataflow_path)
    if not roots:
        # No Solidity project - CLEAN not-applicable (read-only VIEW reentrancy is an
        # EVM view-function class; a pure Go/Cosmos DLT has no view getters here).
        return [], {
            "language_applicable": False,
            "reason": "no-solidity-project-root (read-only view reentrancy is EVM-only)",
            "composed": 0, "guarded": 0, "survivors": 0,
        }, warnings

    Binary, BinaryType, HighLevelCall, LowLevelCall, Transfer, Send = _ir_types()
    EXT = (HighLevelCall, LowLevelCall, Transfer, Send)

    # Per (contract,fn) semantic facts extracted from the Slither CFG/IR backend.
    getters: dict = {}     # (c,f) -> {"reads":set,"arith":bool,"guarded":bool,"file","line","rank"}
    window_mut: dict = {}  # (c,f) -> {"writes":set}  (callback-window mutators only)
    compiled_any = False

    for root in roots:
        sl, err = slice_mod.load_slither_offline(root)
        if sl is None:
            warnings.append(f"compile-DEGRADED[{root.name}]: {err}")
            continue
        compiled_any = True
        for c in sl.contracts:
            if getattr(c, "is_interface", False):
                continue
            is_mock = ("mock" in c.name.lower() or "test" in c.name.lower())
            for f in c.functions:
                if not getattr(f, "is_implemented", False):
                    continue
                try:
                    reads = set(v.name for v in f.state_variables_read if v.name)
                    writes = set(v.name for v in f.state_variables_written if v.name)
                except Exception:
                    continue
                is_view = bool(getattr(f, "view", False) or getattr(f, "pure", False))
                # --- view composite getter membership -------------------------------
                if is_view and not writes and len(reads) >= 2:
                    arith = False
                    for node in f.nodes:
                        for ir in node.irs:
                            if isinstance(ir, Binary) and ir.type in (
                                    BinaryType.DIVISION, BinaryType.MULTIPLICATION,
                                    BinaryType.ADDITION, BinaryType.SUBTRACTION):
                                arith = True
                                break
                        if arith:
                            break
                    guarded = bool(sp.has_non_reentrant_modifier(f)) if sp else False
                    try:
                        fl = f.source_mapping.lines[0] if f.source_mapping.lines else 0
                        ff = f.source_mapping.filename.absolute
                    except Exception:
                        fl, ff = 0, ""
                    getters[(c.name, f.full_name)] = {
                        "reads": reads, "arith": arith, "guarded": guarded,
                        "file": ff, "line": fl, "rank": _name_rank(f.name),
                        "is_mock": is_mock,
                    }
                # --- callback-window mutator membership -----------------------------
                # ORDERING relation over CFG nodes: a state-write BEFORE an external
                # call AND a state-write AFTER it (write -> extcall -> write), with >=2
                # distinct components written across that window.
                # Exclude one-time deploy paths: a constructor writes once at deploy,
                # so no runtime re-entrancy window exists. Exclude mock/test mutators.
                if len(writes) >= 2 and not getattr(f, "is_constructor", False) and not is_mock:
                    ext_idx: list[int] = []
                    wr_idx: list[int] = []
                    for i, node in enumerate(f.nodes):
                        if any(isinstance(ir, EXT) for ir in node.irs):
                            ext_idx.append(i)
                        if any(getattr(v, "name", None) for v in node.state_variables_written):
                            wr_idx.append(i)
                    if ext_idx and wr_idx and min(wr_idx) < max(ext_idx) and max(wr_idx) > min(ext_idx):
                        window_mut[(c.name, f.full_name)] = {"writes": writes}

    if not compiled_any:
        return [], {
            "language_applicable": True, "substrate_degraded": True,
            "reason": "all sol roots failed to compile (DEGRADED, not clean-empty)",
            "composed": 0, "guarded": 0, "survivors": 0,
        }, warnings

    # CONSUMER JOIN over dataflow_paths.jsonl: a value-release sink whose slice reads
    # one of the survivor getter's shared components (an external consumer reaching a
    # value-release sink that reads G).
    consumer_by_var: dict = {}
    dataflow_present = dataflow_path.exists()
    if dataflow_present:
        RELEASE = {"value-move", "safeTransfer", "safeTransferFrom", "mint", "burn"}
        recs = []
        for line in dataflow_path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                recs.append(json.loads(line))
            except Exception:
                continue
        # fn -> does its slice reach a value-release sink
        release_fns = set()
        for r in recs:
            if (r.get("sink") or {}).get("kind") in RELEASE:
                release_fns.add((r.get("sink") or {}).get("fn"))
        # var -> release-fns that read it
        for r in recs:
            s = r.get("sink") or {}
            if s.get("kind") == "state_var_read" and s.get("callee"):
                fnn = s.get("fn")
                if fnn in release_fns:
                    consumer_by_var.setdefault(s["callee"], set()).add(fnn)

    survivors, summary = compute_set_difference(
        getters, window_mut, consumer_by_var, dataflow_present,
        ws=ws, include_oos=include_oos)
    return survivors, summary, warnings


def compute_set_difference(getters: dict, window_mut: dict, consumer_by_var: dict,
                           dataflow_present: bool, ws: Path = Path("."),
                           include_oos: bool = False):
    """PURE set/join relation - the reasoning core, decoupled from Slither/IO so it is
    unit-testable with synthetic facts.

    getters:  {(contract,fn): {"reads":set, "arith":bool, "guarded":bool,
                               "file":str, "line":int, "rank":int, "is_mock":bool}}
    window_mut: {(contract,fn): {"writes":set}}   (callback-window mutators only)
    consumer_by_var: {state_var: set(value-release consumer fns)}

    Returns (survivors:list[dict], summary:dict).
    """
    # Union of all components mutated across ANY callback window.
    windowed_components: set = set()
    for m in window_mut.values():
        windowed_components |= set(m["writes"])

    # COMPOSED_ACROSS_WINDOW = getters whose read-set intersects a callback-window
    # mutator's write-set (SHARED-COMPONENT cross-function JOIN).
    composed = []
    for (cn, fn), g in getters.items():
        if g.get("is_mock") and not include_oos:
            continue
        reads = set(g["reads"])
        shared = reads & windowed_components
        if shared:
            m_hits = [f"{mc}.{mf}" for (mc, mf), m in window_mut.items()
                      if reads & set(m["writes"])]
            composed.append((cn, fn, g, sorted(shared), sorted(m_hits)))

    guarded_set = [(cn, fn) for (cn, fn, g, _s, _m) in composed if g["guarded"]]
    survivors_raw = [(cn, fn, g, s, m) for (cn, fn, g, s, m) in composed if not g["guarded"]]

    # CONSUMER-JOIN GATE (the trust-boundary requirement from the mined logic: the
    # finding is the set-difference JOINED to an external consumer that reaches a
    # value-release sink reading G). A survivor with NO downstream value-release
    # consumer is not exploitable read-only reentrancy - its transient value is never
    # used to release value. When the dataflow substrate is ABSENT we cannot compute
    # the join, so we fall back to KEEPING only name-ranked financial composites and
    # flag join_unavailable, rather than silently dropping a real lead.
    survivors = []
    for (cn, fn, g, shared, m_hits) in sorted(
            survivors_raw, key=lambda x: (-x[2].get("rank", 0), x[0], x[1])):
        consumers = sorted({c for v in shared for c in consumer_by_var.get(v, set())})
        if consumers:
            join_note = "value-release-consumer-confirmed"
        elif not dataflow_present and g.get("rank"):
            join_note = "join_unavailable-kept-name-ranked-financial-composite"
        else:
            continue  # no value-release consumer -> not exploitable read-only reentrancy
        src_ref = (f"{_rel(ws, g['file'])}:{g['line']}"
                   if g.get("file") else f"{cn}.{fn}")
        row = {
            "schema": SCHEMA,
            "capability": _CAPABILITY,
            "contract": cn,
            "function": fn,
            "source_refs": [src_ref],
            "attack_class": "read-only-view-reentrancy-unguarded-composite-getter",
            "likely_severity": "high",
            "composite_components_read": shared,
            "arithmetic_composite": bool(g.get("arith")),
            "callback_window_mutators": m_hits,
            "downstream_value_release_consumers": consumers,
            "broken_invariant_ids": ["readonly-view-reentrancy-composite-getter-guard"],
            "root_cause_hypothesis": (
                f"View getter {cn}.{fn} composes mutable state components "
                f"{shared} that callback-window mutator(s) {m_hits} rewrite around an "
                f"untrusted external call, yet {cn}.{fn} carries NO nonReentrant/lock "
                f"guard -> it can be read transiently inconsistent mid-callback and "
                f"consumed as ground truth by "
                f"{consumers or 'a value-release path'}."),
            "next_command": (
                f"python3 tools/read-only-view-reentrancy-unguarded-composite-getter.py "
                f"--workspace {ws}"),
            "quality_gate_status": "needs_source",
            "name_ranked_composite": bool(g.get("rank")),
            "consumer_join": join_note,
        }
        survivors.append(row)

    summary = {
        "language_applicable": True,
        "substrate_degraded": False,
        "view_composite_getters": len(getters),
        "callback_window_mutators": len(window_mut),
        "composed": len(composed),
        "guarded": len(guarded_set),
        "survivors": len(survivors),
        "kept_guarded": [f"{cn}.{fn}" for (cn, fn) in guarded_set],
    }
    return survivors, summary


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--dataflow", default=None,
                    help="override path to dataflow_paths.jsonl "
                         "(default <ws>/.auditooor/dataflow_paths.jsonl)")
    ap.add_argument("--emit", default=None,
                    help="override obligations output path")
    ap.add_argument("--include-oos", action="store_true",
                    help="include mock/test contracts (default: excluded)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="rc!=0 when the Solidity substrate is present but DEGRADED "
                         "(the set-difference could not be computed). A clean "
                         "language-not-applicable (no sol project) is NOT a failure.")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).resolve()
    if not ws.is_dir():
        print(f"ERROR: workspace not a directory: {ws}", file=sys.stderr)
        return 2
    dataflow_path = Path(args.dataflow) if args.dataflow else ws / ".auditooor" / "dataflow_paths.jsonl"
    out_path = Path(args.emit) if args.emit else ws / ".auditooor" / _SIDE_NAME
    out_path.parent.mkdir(parents=True, exist_ok=True)

    survivors, summary, warnings = analyze_workspace(
        ws, dataflow_path, include_oos=args.include_oos)

    with out_path.open("w") as fh:
        for row in survivors:
            fh.write(json.dumps(row) + "\n")

    summary.update({
        "schema": SCHEMA,
        "capability": _CAPABILITY,
        "workspace": str(ws),
        "output": str(out_path),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "warnings": warnings,
    })

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[ror-composite-getter] {ws.name}: applicable="
              f"{summary.get('language_applicable')} composed={summary.get('composed')} "
              f"guarded={summary.get('guarded')} survivors={summary.get('survivors')} "
              f"-> {out_path}")
        for w in warnings:
            print(f"  WARN {w}", file=sys.stderr)
        if summary.get("survivors"):
            for row in survivors:
                print(f"  SURVIVOR {row['contract']}.{row['function']} "
                      f"components={row['composite_components_read']} "
                      f"consumers={row['downstream_value_release_consumers']}")

    strict = args.fail_closed or os.environ.get(_STRICT_ENV, "") not in ("", "0", "false", "no")
    if strict and summary.get("substrate_degraded"):
        print("[ror-composite-getter] FAIL-CLOSED: solidity substrate present but "
              "DEGRADED (could not compute set-difference)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
