#!/usr/bin/env python3
"""
storage-layout.py — R76 E: proxy / diamond storage-layout analyzer.

Dumps the storage layout of every non-interface non-library contract and
flags these patterns that top auditors look for:

  1. Proxy + implementation slot mismatch: if ProxyContract has state vars
     but the implementation it delegatecalls to has a DIFFERENT layout at
     the same slot indices, bytes collide.
  2. Unnamespaced diamond facets (EIP-2535): if multiple facets write to
     the same global slot.
  3. Upgrade-v2 contract adds a NEW state var BEFORE existing ones →
     shifts all later slots → silent corruption after upgrade.
  4. Packed-struct member order reshuffle across versions.

Output: <workspace>/storage_layout.md

Usage:
  python3 tools/storage-layout.py <workspace>
  python3 tools/storage-layout.py <workspace> --compare-dir <old-source-dir>
    (compare current layout vs prior version in another dir — detect shifts)
"""

import argparse, pathlib, sys, re
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _analyzer_common import iter_source_files

try:
    from slither.slither import Slither
except ImportError:
    print("[err] Slither required", file=sys.stderr); sys.exit(1)


def _compute_layout(contract):
    """Return list of {name, type, slot, offset, size_bytes}."""
    layout = []
    slot = 0
    offset = 0
    def sizeof(t):
        s = str(t)
        if s == "address" or "contract " in s: return 20
        if s == "bool": return 1
        if s.startswith("uint") or s.startswith("int"):
            try:
                n = int(s.lstrip("uint").lstrip("int") or "256")
                return n // 8
            except Exception: return 32
        if s.startswith("bytes") and len(s) > 5:
            try: return int(s[5:])
            except Exception: return 32
        if "[]" in s or "mapping" in s or "bytes" == s or "string" == s:
            return 32
        return 32  # structs etc — conservative

    for sv in (getattr(contract, "state_variables_ordered", []) or []):
        # Skip constants + immutables (not stored)
        if getattr(sv, "is_constant", False) or getattr(sv, "is_immutable", False):
            continue
        sz = sizeof(sv.type)
        if offset + sz > 32:
            slot += 1; offset = 0
        layout.append({
            "name": sv.name, "type": str(sv.type),
            "slot": slot, "offset": offset, "size": sz,
        })
        offset += sz
        if offset >= 32:
            slot += 1; offset = 0
    return layout


def _contracts_from_sources(path):
    """Walk src/ for .sol files, parse each, yield (file, contract_obj)."""
    for sol in iter_source_files(path, max_files=200):  # R79 T3
        try: sl = Slither(str(sol))
        except Exception: continue
        for c in sl.contracts:
            if c.is_interface or c.is_library: continue
            yield sol, c


def _diff_layouts(old_layout, new_layout):
    """Pure (Slither-free) layout differ for upgradeable-storage corruption.

    Inputs are two lists of layout dicts as produced by `_compute_layout`
    (each {name, type, slot, offset, size}). Returns a list of finding dicts:

      {"kind": "slot-shift",  "name", "old_slot", "new_slot"}
          a state var that existed in the OLD version now sits at a DIFFERENT
          slot index -> the layout moved under it -> every byte at the moved
          slot reads/writes the WRONG storage post-upgrade (Critical-class
          silent storage corruption). BOTH directions are a corruption signal:
            - UPWARD (new_slot > old_slot): a var was INSERTED before it.
            - DOWNWARD (new_slot < old_slot): a var was REMOVED before it (or a
              type-shrink repacked a later var into an earlier slot), so the
              survivor now collides with whatever the proxy already stored at
              the lower slot. Removals are surfaced HERE, via this downward
              shift, not as a standalone "removed var" finding.
      {"kind": "offset-shift","name", "old_offset", "new_offset", "slot"}
          a var keeps its slot but its packed offset within the word moved
          -> packed-struct / packed-var member reorder (sub-slot corruption).
      {"kind": "type-change",  "name", "old_type", "new_type", "slot"}
          a var at the same slot changed declared type width -> the bytes are
          reinterpreted (e.g. uint128 -> uint256 swallows the next field).

    Detection is keyed by variable NAME (the stable identity across an
    upgrade). A var renamed AND moved is reported as slot-shift on the new
    name only if the name still matches; pure additions/removals are not
    themselves flagged here - their corruption is surfaced via the SLOT SHIFT
    (either direction) they force on the SURVIVING vars, which is the actual
    proxy-collision signal. An insertion shifts survivors UP; a removal (or a
    type-shrink that lets a later var repack lower) shifts survivors DOWN.
    """
    old_by_name = {v["name"]: v for v in old_layout}
    findings = []
    for nv in new_layout:
        ov = old_by_name.get(nv["name"])
        if ov is None:
            continue  # newly-added var; corruption shows up as a shift on others
        # (a) slot index CHANGED (either direction) -> the layout moved under a
        #     surviving var. UPWARD = insertion before it; DOWNWARD = removal
        #     before it (or a type-shrink repack). Both are silent storage
        #     corruption against whatever the proxy already stored at that slot.
        if nv["slot"] != ov["slot"]:
            findings.append({
                "kind": "slot-shift",
                "name": nv["name"],
                "old_slot": ov["slot"],
                "new_slot": nv["slot"],
                "direction": "up" if nv["slot"] > ov["slot"] else "down",
            })
        # (b) same slot but packed offset moved -> packed reorder.
        elif nv["slot"] == ov["slot"] and nv["offset"] != ov["offset"]:
            findings.append({
                "kind": "offset-shift",
                "name": nv["name"],
                "slot": nv["slot"],
                "old_offset": ov["offset"],
                "new_offset": nv["offset"],
            })
        # (c) type-width change at the (still-same) slot -> reinterpretation.
        if nv["slot"] == ov["slot"] and nv["type"] != ov["type"]:
            findings.append({
                "kind": "type-change",
                "name": nv["name"],
                "slot": nv["slot"],
                "old_type": ov["type"],
                "new_type": nv["type"],
            })
    return findings


def _compare_dir_contracts(ws_contracts, old_dir):
    """Build {contract_name: [findings]} by diffing each contract present in
    BOTH the current workspace and the old source dir.

    `ws_contracts` is the already-parsed list of (file, contract) from the
    current workspace. The old dir is parsed fresh here. Only contracts whose
    name appears in both trees are compared.
    """
    old_contracts = list(_contracts_from_sources(pathlib.Path(old_dir)))
    old_by_name = {}
    for _sol, c in old_contracts:
        old_by_name.setdefault(c.name, c)  # first wins; dupes are a smell
    results = {}
    for _sol, c in ws_contracts:
        oc = old_by_name.get(c.name)
        if oc is None:
            continue
        findings = _diff_layouts(_compute_layout(oc), _compute_layout(c))
        if findings:
            results[c.name] = findings
    return results


def _detect_proxy_pairs(contracts):
    """Heuristic: proxy if has `_implementation` slot + delegatecall pattern.
    Pair it with the implementation by name-match (FooProxy → Foo, or
    FooUpgradeable → FooImpl)."""
    proxies = []
    impls = {}
    for sol, c in contracts:
        txt = ""
        try:
            with open(sol) as f: txt = f.read()
        except Exception: pass
        has_delegate = "delegatecall" in txt.lower()
        has_impl_slot = "implementation" in txt.lower() and ("_delegate" in txt.lower() or "fallback" in txt.lower())
        if has_delegate and has_impl_slot:
            proxies.append((sol, c))
        # Store by name for impl lookup
        impls[c.name] = (sol, c)
    pairs = []
    for sol, prx in proxies:
        cands = [
            prx.name.replace("Proxy", ""),
            prx.name.replace("UUPS", ""),
            prx.name + "Impl",
            prx.name + "Implementation",
        ]
        for cand in cands:
            if cand in impls and impls[cand][1].name != prx.name:
                pairs.append((prx, impls[cand][1]))
                break
    return pairs


def _detect_diamond_facets(contracts):
    """Identify all facets (contracts named *Facet or participating in a
    Diamond). Return list of facet contracts."""
    facets = []
    for sol, c in contracts:
        if c.name.endswith("Facet") or "DiamondCut" in [getattr(m, "name", "") for m in getattr(c, "inheritance", [])]:
            facets.append((sol, c))
    return facets


def _render_compare_section(f, compare_results, old_dir):
    """Write the upgrade-shift section. `compare_results` is the dict from
    `_compare_dir_contracts`. Writes a clean note when nothing was flagged."""
    f.write("\n## Upgrade storage-shift vs prior version\n\n")
    f.write(f"Compared against prior source dir `{old_dir}`. "
            "Flags state vars whose slot/offset/type moved across the upgrade "
            "(silent storage corruption after a proxy upgrade).\n\n")
    if not compare_results:
        f.write("_No storage-layout shifts detected vs prior version. "
                "Surviving state vars keep their slot, offset and type._\n\n")
        return
    for cname in sorted(compare_results.keys()):
        f.write(f"\n### CRITICAL: `{cname}` layout shifted across upgrade\n\n")
        for fd in compare_results[cname]:
            if fd["kind"] == "slot-shift":
                cause = (
                    "a var was inserted BEFORE it; later slots now collide"
                    if fd.get("direction") == "up" or fd["new_slot"] > fd["old_slot"]
                    else "a var was REMOVED before it (or a type-shrink repacked a "
                         "later var lower); it now collides with the proxy's "
                         "existing lower-slot storage"
                )
                f.write(
                    f"- slot-shift: `{fd['name']}` moved slot "
                    f"{fd['old_slot']} -> {fd['new_slot']} ({cause})\n"
                )
            elif fd["kind"] == "offset-shift":
                f.write(
                    f"- packed-reorder: `{fd['name']}` (slot {fd['slot']}) "
                    f"offset {fd['old_offset']} -> {fd['new_offset']} "
                    "(packed member reshuffle; sub-slot bytes corrupt)\n"
                )
            elif fd["kind"] == "type-change":
                f.write(
                    f"- type-width-change: `{fd['name']}` (slot {fd['slot']}) "
                    f"`{fd['old_type']}` -> `{fd['new_type']}` "
                    "(stored bytes reinterpreted)\n"
                )


def _render(ws_contracts, proxy_pairs, facets, out, compare_results=None, old_dir=None):
    with open(out, "w") as f:
        f.write("# Storage-layout report\n\n")
        f.write("Generated by `tools/storage-layout.py`. Shows slot layout "
                "for every non-interface contract, plus flags proxy/impl "
                "pairs with possible layout mismatches.\n\n")

        if compare_results is not None:
            _render_compare_section(f, compare_results, old_dir)

        # Proxy/impl mismatch
        f.write("## ⚠️ Proxy / implementation pairs\n\n")
        if not proxy_pairs:
            f.write("_No proxy/implementation pairs detected heuristically._\n\n")
        else:
            for prx, impl in proxy_pairs:
                f.write(f"\n### `{prx.name}` ↔ `{impl.name}`\n\n")
                p_layout = _compute_layout(prx)
                i_layout = _compute_layout(impl)
                # Show any collision at slot 0..5
                f.write("| Slot | Proxy | Implementation | Match? |\n|---|---|---|---|\n")
                max_slot = max(
                    (l["slot"] for l in p_layout + i_layout), default=-1
                )
                for s in range(min(max_slot + 1, 8)):
                    p_at = [l for l in p_layout if l["slot"] == s]
                    i_at = [l for l in i_layout if l["slot"] == s]
                    p_desc = ", ".join(f"`{v['name']}` ({v['type']})" for v in p_at) or "—"
                    i_desc = ", ".join(f"`{v['name']}` ({v['type']})" for v in i_at) or "—"
                    ok = "✅" if p_desc == i_desc else ("⚠️" if p_at and i_at else "—")
                    f.write(f"| {s} | {p_desc} | {i_desc} | {ok} |\n")

        # Diamond facet slot collisions
        f.write("\n## Diamond facets (EIP-2535)\n\n")
        if not facets:
            f.write("_No diamond facets detected._\n\n")
        else:
            writes_by_slot = defaultdict(list)   # slot → [(facet, var)]
            for sol, c in facets:
                layout = _compute_layout(c)
                for v in layout:
                    writes_by_slot[v["slot"]].append((c.name, v["name"], v["type"]))
            for s in sorted(writes_by_slot.keys()):
                writers = writes_by_slot[s]
                if len(writers) > 1:
                    f.write(f"\n**⚠️ Slot {s} declared by multiple facets:**\n")
                    for c, name, typ in writers:
                        f.write(f"  - `{c}.{name}` ({typ})\n")

        # Full per-contract layouts
        f.write("\n## Per-contract layouts\n\n")
        for sol, c in ws_contracts:
            layout = _compute_layout(c)
            if not layout: continue
            f.write(f"\n### `{c.name}` (`{sol.relative_to(sol.parents[2]) if len(sol.parents) >= 2 else sol.name}`)\n\n")
            f.write("| Slot | Offset | Size | Name | Type |\n|---:|---:|---:|---|---|\n")
            for v in layout:
                f.write(f"| {v['slot']} | {v['offset']} | {v['size']} | `{v['name']}` | `{v['type']}` |\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("workspace")
    ap.add_argument(
        "--compare-dir",
        default=None,
        help="prior-version source dir; diff current layout vs it to flag "
             "insertion-before-existing slot shifts, packed-member reorders "
             "and type-width changes (upgradeable-storage corruption).",
    )
    args = ap.parse_args()
    ws = pathlib.Path(args.workspace)
    if not ws.is_dir(): print("[err] not a dir", file=sys.stderr); sys.exit(1)
    contracts = list(_contracts_from_sources(ws))
    proxy_pairs = _detect_proxy_pairs(contracts)
    facets = _detect_diamond_facets(contracts)
    compare_results = None
    if args.compare_dir is not None:
        old_dir = pathlib.Path(args.compare_dir)
        if not old_dir.is_dir():
            print("[err] --compare-dir not a dir", file=sys.stderr); sys.exit(1)
        compare_results = _compare_dir_contracts(contracts, old_dir)
    out = ws / "storage_layout.md"
    _render(contracts, proxy_pairs, facets, out,
            compare_results=compare_results, old_dir=args.compare_dir)
    print(f"[ok] wrote {out}")
    print(f"     contracts: {len(contracts)} | proxy pairs: {len(proxy_pairs)} | facets: {len(facets)}")
    if compare_results is not None:
        n = sum(len(v) for v in compare_results.values())
        print(f"     compare-dir: {len(compare_results)} shifted contract(s) | {n} shift(s)")


if __name__ == "__main__":
    main()
