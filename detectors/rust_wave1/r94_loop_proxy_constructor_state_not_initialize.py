"""
r94_loop_proxy_constructor_state_not_initialize.py

Flags contracts marked upgradeable (UUPS / Initializable / has
`initialize()`) whose `new()` / `constructor` sets state fields —
proxy delegatecall skips the constructor, so state never lands in
proxy storage.

Source: Solodit #19448 (SigmaPrime Infinigold TokenImpl).
Class: proxy-constructor-state-not-initialize (both).
"""

from __future__ import annotations
import re
from _util import source_nocomment

_UPGRADEABLE_MARKER_RE = re.compile(
    r"Initializable|UUPSUpgradeable|OwnableUpgradeable|ContextUpgradeable|fn\s+initialize\s*\("
)
_CTOR_SETS_STATE_RE = re.compile(
    r"(constructor|fn\s+new)\s*\([^)]*\)[^{]{0,100}\{[^}]{0,500}?(owner\s*=|name\s*=|symbol\s*=|decimals\s*=|admin\s*=)",
    re.DOTALL,
)


def run(tree, source: bytes, filepath: str):
    hits = []
    src = source_nocomment(source)
    if not _UPGRADEABLE_MARKER_RE.search(src):
        return hits
    m = _CTOR_SETS_STATE_RE.search(src)
    if not m:
        return hits
    # rough line guess: count newlines up to match
    line = src.count("\n", 0, m.start()) + 1
    hits.append({
        "severity": "high",
        "line": line,
        "col": 0,
        "snippet": src[m.start():m.start()+200],
        "message": (
            "Upgradeable contract's constructor sets state "
            "(owner/name/admin) — proxy delegatecall skips ctor, "
            "state never lands in proxy storage (proxy-constructor-"
            "state-not-initialize). See Solodit #19448 (Infinigold)."
        ),
    })
    return hits
