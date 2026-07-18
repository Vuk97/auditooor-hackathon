"""
r94_loop_uups_implementation_takeover_destroy.py

Flags UUPSUpgradeable-style impl contracts (has initialize / authorize_upgrade)
whose constructor does NOT call `_disable_initializers()` — attacker
initializes impl directly and then upgrades it to self-destruct.

Source: Solodit #25544 (C4 Notional), #19456 (Lido), #18130 (Morpho).
Class: uups-implementation-takeover-destroy (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of,
    is_pub, body_text_nocomment, source_nocomment,
)

_UUPS_MARKER_RE = re.compile(r"UUPSUpgradeable|upgrade_to(_and_call)?|authorize_upgrade|_authorize_upgrade")
_INITIALIZE_RE = re.compile(r"fn\s+initialize\s*\(|fn\s+init\s*\(")
_DISABLE_INIT_RE = re.compile(
    r"_disable_initializers\s*\(\s*\)|disable_initializers|"
    r"constructor\s*\([^)]*\)\s*\{[^}]*_disable_initializers"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    src = source_nocomment(source)
    if not _UUPS_MARKER_RE.search(src):
        return hits
    if not _INITIALIZE_RE.search(src):
        return hits
    if _DISABLE_INIT_RE.search(src):
        return hits
    # pick the initialize fn as anchor
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        name = fn_name(fn, source)
        if name not in ("initialize", "init"):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"UUPS-upgradeable contract has `initialize()` but no "
                f"`_disable_initializers()` in constructor/ctor — "
                f"attacker initializes impl, upgrades to self-destruct "
                f"impl, proxy breaks (uups-implementation-takeover-"
                f"destroy). See Solodit #25544 (Notional)."
            ),
        })
        break
    return hits
