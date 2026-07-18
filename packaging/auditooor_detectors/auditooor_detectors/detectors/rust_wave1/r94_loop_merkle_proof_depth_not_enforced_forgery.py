"""
r94_loop_merkle_proof_depth_not_enforced_forgery.py

Flags merkle-verify fns that iterate `proof` elements without
requiring `proof.len() == TREE_DEPTH` — attacker passes shorter
proof that still reconstructs a valid root via length ambiguity.

Source: Solodit #21288 (TrailOfBits Succinct Telepathy).
Class: merkle-proof-depth-not-enforced-forgery (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(verify_merkle|verify_branch|verify_proof|merkle_verify|is_valid_merkle_proof)")
_PROOF_ITER_RE = re.compile(
    fr"for\s+\w+\s+in\s+{IDENT}(proof|branch|siblings)|"
    fr"{IDENT}(proof|branch|siblings)\s*\.\s*iter\s*\(|"
    fr"{IDENT}(proof|branch|siblings)\s*\[\s*\w+\s*\]"
)
_DEPTH_CHECK_RE = re.compile(
    fr"(require\s*\(\s*{IDENT}(proof|branch)\.length\s*==\s*\w+|"
    fr"assert[!_]?\s*\(\s*{IDENT}(proof|branch)\.len\s*\(\s*\)\s*==\s*{IDENT}(DEPTH|TREE_DEPTH|depth)|"
    fr"{IDENT}(proof|branch)\.len\s*\(\s*\)\s*==\s*{IDENT}(DEPTH|depth))"
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
        if not _PROOF_ITER_RE.search(body_nc):
            continue
        if _DEPTH_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` iterates merkle proof without "
                f"requiring `proof.len() == TREE_DEPTH` — attacker "
                f"passes shorter proof that reconstructs a valid "
                f"root (merkle-proof-depth-not-enforced-forgery). "
                f"See Solodit #21288 (Succinct Labs Telepathy)."
            ),
        })
    return hits
