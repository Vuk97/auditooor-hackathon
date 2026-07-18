"""
r94_loop_eip712_domain_separator_immutable_forks_unsafe.py

Flags contracts that cache DOMAIN_SEPARATOR (or `domain_separator`)
as `immutable` / `const` / at-construction value using block.chainid
without a runtime refresh on chainid change.

Source: Solodit #27801 (MixBytes Bebop).
Class: eip712-domain-separator-immutable-forks-unsafe (both).
"""

from __future__ import annotations
import re
from _util import source_nocomment, IDENT, CALL

_IMMUTABLE_DOMAIN_RE = re.compile(
    r"(bytes32\s+(public\s+)?(immutable|constant)\s+DOMAIN_SEPARATOR\s*=|"
    r"const\s+DOMAIN_SEPARATOR\s*:\s*\[u8;\s*32\]\s*=|"
    r"static\s+DOMAIN_SEPARATOR\s*:\s*.+?=\s*build_separator)"
)
_RUNTIME_REFRESH_RE = re.compile(
    fr"(_domain_separator_v4\s*\(|_buildDomainSeparator\s*\(|"
    fr"block\.chainid\s*==\s*{IDENT}cached_chain_id|"
    fr"if\s+block\.chainid\s*!=\s*cached_chain_id|"
    fr"ERC712Upgradeable\.__EIP712_init)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    src = source_nocomment(source)
    if not _IMMUTABLE_DOMAIN_RE.search(src):
        return hits
    if _RUNTIME_REFRESH_RE.search(src):
        return hits
    m = _IMMUTABLE_DOMAIN_RE.search(src)
    line = src.count("\n", 0, m.start()) + 1
    hits.append({
        "severity": "high",
        "line": line,
        "col": 0,
        "snippet": src[m.start():m.start()+200],
        "message": (
            "Contract caches DOMAIN_SEPARATOR at construction without "
            "runtime chainid check / refresh — fork / chainid change "
            "makes sigs signed on new chain replayable on old "
            "(eip712-domain-separator-immutable-forks-unsafe). See "
            "Solodit #27801 (Bebop)."
        ),
    })
    return hits
