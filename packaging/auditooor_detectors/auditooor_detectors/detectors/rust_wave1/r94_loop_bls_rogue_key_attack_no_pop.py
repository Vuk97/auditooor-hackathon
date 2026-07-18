"""
r94_loop_bls_rogue_key_attack_no_pop.py

Flags BLS aggregate-verify / processBundle fns that aggregate public
keys without a proof-of-possession (PoP) check — attacker registers
rogue_pk = sum(-pk_i) + own_pk so aggregated sig verifies under
any set.

Source: Solodit #19278 (SigmaPrime BLS Wallet).
Class: bls-rogue-key-attack-no-pop (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(process_bundle|aggregate_verify|verify_aggregate|bls_verify|register_key|add_pubkey|add_validator)")
_AGG_RE = re.compile(
    fr"(aggregate\w*\s*\(|"
    fr"{IDENT}pubkey\w*\s*\+\s*{IDENT}pubkey|"
    fr"sum\s*::\s*<|"
    fr"\.\s*iter\s*\(\s*\)\s*\.\s*fold|"
    fr"\.\s*iter\s*\(\s*\)\s*\.\s*sum|"
    fr"g1_add|g2_add)"
)
_POP_RE = re.compile(
    r"(?i)(proof_of_possession|verify_pop|check_pop|"
    r"pop_verify|pop_check|"
    r"knowledge_of_secret_key|kosk)"
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
        if not _AGG_RE.search(body_nc):
            continue
        if _POP_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` aggregates BLS pubkeys without a "
                f"proof-of-possession check — attacker crafts rogue "
                f"pk = -sum(existing) + own so aggregated sig "
                f"verifies under any set (bls-rogue-key-attack-no-pop). "
                f"See Solodit #19278 (SigmaPrime BLS Wallet)."
            ),
        })
    return hits
