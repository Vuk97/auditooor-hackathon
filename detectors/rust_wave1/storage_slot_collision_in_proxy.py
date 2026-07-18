"""
storage_slot_collision_in_proxy.py

Flags contracts where the same logical storage key name appears BOTH as a
`DataKey::<Variant>` (enum key) and as a `symbol_short!("variant")` /
`Symbol::new(&env, "variant")` literal — proxy-upgrade-style collision: a
new version reads the DataKey-encoded slot, an old version wrote the
Symbol-encoded slot (or vice versa).

Heuristic:
  1. Collect enum_variant names under any `enum DataKey {...}`.
  2. Collect all `symbol_short!("...")` / `Symbol::new(&env, "...")`
     string literals in the file.
  3. For each variant name whose lowercased form == a literal's
     lowercased form → emit a hit.
"""

from __future__ import annotations

import re

from _util import text_of, walk, line_col, snippet_of


def _datakey_variants(root, source: bytes) -> list[tuple[str, object]]:
    variants = []
    for n in walk(root):
        if n.type != "enum_item":
            continue
        # name
        name = None
        for c in n.children:
            if c.type == "type_identifier":
                name = text_of(c, source)
                break
        if name not in ("DataKey", "Key"):
            continue
        # enum_variant_list → enum_variant → identifier
        for c in n.children:
            if c.type == "enum_variant_list":
                for v in c.children:
                    if v.type != "enum_variant":
                        continue
                    for vc in v.children:
                        if vc.type == "identifier":
                            variants.append((text_of(vc, source), v))
                            break
    return variants


def _symbol_literals(root, source: bytes) -> list[tuple[str, object]]:
    out = []
    for n in walk(root):
        if n.type != "call_expression" and n.type != "macro_invocation":
            continue
        t = text_of(n, source)
        if "symbol_short!" in t or "Symbol::new" in t:
            m = re.search(r'"([A-Za-z_][A-Za-z0-9_]*)"', t)
            if m:
                out.append((m.group(1), n))
    return out


def run(tree, source: bytes, filepath: str):
    root = tree.root_node
    variants = _datakey_variants(root, source)
    if not variants:
        return []
    lits = _symbol_literals(root, source)
    if not lits:
        return []

    variant_lc = {v.lower(): (v, node) for v, node in variants}
    hits = []
    seen = set()
    for lit, lnode in lits:
        if lit.lower() in variant_lc:
            vname, _vnode = variant_lc[lit.lower()]
            key = (vname, lit)
            if key in seen:
                continue
            seen.add(key)
            line, col = line_col(lnode)
            hits.append({
                "severity": "low",
                "line": line,
                "col": col,
                "snippet": snippet_of(lnode, source),
                "message": (
                    f"Symbol literal `\"{lit}\"` mirrors the "
                    f"`DataKey::{vname}` enum variant — same logical key "
                    f"encoded two different ways, risk of slot collision "
                    f"across upgrades."
                ),
            })
    return hits
