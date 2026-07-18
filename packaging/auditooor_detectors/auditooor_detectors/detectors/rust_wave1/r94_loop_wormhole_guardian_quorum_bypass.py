"""
r94_loop_wormhole_guardian_quorum_bypass.py

Flags VAA-verification fns that accept a VAA without checking the
signatures.len() >= guardian_set_quorum() (or hardcoded 13-of-19 for
Wormhole's standard set).

Source: Wormhole-family bridge integrations across Solodit.
Class: wormhole-guardian-quorum (both).
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_FN_NAME_RE = re.compile(
    r"(?i)(verify_vaa|parse_vaa|process_vaa|complete_transfer|"
    r"on_vaa|receive_message|verify_guardian|parse_and_verify)"
)

_SIG_READ_RE = re.compile(
    r"\bsignatures\b|\bguardian_signatures\b|\bvaa\.signatures\b|"
    r"\.sig_count\b"
)

_QUORUM_CHECK_RE = re.compile(
    r"signatures\.len\s*\(\s*\)\s*>=|"
    r"\.len\s*\(\s*\)\s*>=\s*(quorum|threshold|\d+)|"
    r"guardian_set\.quorum\s*\(\)|"
    r"require!?\s*\([^)]*(signatures|sig_count)\s*(>=|>)|"
    r"check_quorum|verify_quorum|assert_quorum"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)

        if not _SIG_READ_RE.search(body_nc):
            continue
        if _QUORUM_CHECK_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reads VAA signatures but never enforces "
                f"`signatures.len() >= quorum` (or guardian-set quorum). "
                f"A single forged signature could pass verification and "
                f"release bridge funds."
            ),
        })
    return hits
