"""
r94_loop_chainid_cached_at_deploy_fork_replay.py

Flags constructor/initializer fns that cache `chain_id` (or a
chain-id-dependent DOMAIN_SEPARATOR) into storage at deploy/init time
but never rebuild the domain when the chain forks — EIP-712 signatures
become replayable across a hard-fork.

Source: Solodit #17657 (TrailOfBits EQLC Advanced Blockchain).
Class: chainid-cached-at-deploy-fork-replay (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(constructor|initialize|init|^new$|setup|"
    r"deploy_init|init_domain|initialize_eip712)"
)
_CACHE_CHAINID_RE = re.compile(
    fr"({IDENT}_CACHED_CHAIN_ID\s*=\s*{IDENT}chain_id|"
    fr"_CACHED_CHAIN_ID\s*=\s*block\.chainid|"
    fr"_CACHED_CHAIN_ID\s*=\s*env\.ledger\s*\(\s*\)\.network_id|"
    fr"_HASHED_DOMAIN_SEPARATOR\s*=\s*{IDENT}compute|"
    fr"DOMAIN_SEPARATOR\s*=\s*keccak\w*\s*\(\s*[^)]*chain_id|"
    fr"self\s*\.\s*chain_id\s*=\s*block\s*\.\s*chainid|"
    fr"self\s*\.\s*chain_id\s*=\s*env\.ledger\(\)\.network_id)"
)
_REBUILD_ON_MISMATCH_RE = re.compile(
    fr"(_domainSeparatorV4|_buildDomainSeparator|"
    fr"if\s+{IDENT}block\.chainid\s*!=\s*{IDENT}_CACHED_CHAIN_ID|"
    fr"if\s+{IDENT}env\s*\.\s*ledger\s*\(\s*\)\s*\.\s*network_id\s*!=|"
    fr"rebuild_domain_separator|recompute_domain|chain_id_changed|"
    fr"reinitialize_domain|"
    fr"getDomainSeparator\s*\(\s*\)\s*\{{\s*[\s\S]*?block\.chainid)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _CACHE_CHAINID_RE.search(body_nc):
            continue
        if _REBUILD_ON_MISMATCH_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} caches chain_id into storage at "
                f"construction/initialize but never rebuilds the domain "
                f"when chain_id changes (fork) — EIP-712 signatures "
                f"replay across hard-fork "
                f"(chainid-cached-at-deploy-fork-replay). "
                f"See Solodit #17657 (TrailOfBits EQLC Advanced Blockchain)."
            ),
        })
    return hits
