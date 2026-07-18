"""
r94_loop_observer_untrusted_role.py

Flags fns gated only by a single observer/relayer role that write into
an inbound-tracker / bridge-success state without a quorum, a proof, or
a source-tx success check.

Source: Solodit #58631 (Sherlock / ZetaChain Cross-Chain).
Rust side of `observer-untrusted-role` canonical class.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_FN_NAME_RE = re.compile(
    r"(?i)(mark_?inbound|confirm_?deposit|attest_?tx|record_?tx|"
    r"notify_?inbound|process_?inbound|add_?inbound_?tx|"
    r"set_?tx_?(success|confirmed|final))"
)

_OBSERVER_GATE_RE = re.compile(
    r"is_observer|is_relayer|only_observer|only_relayer|"
    r"require_observer|require_relayer|observer\.require_auth|"
    r"relayer\.require_auth"
)

_QUORUM_OR_PROOF_RE = re.compile(
    r"quorum|multi_attest|multi_observer|"
    r"merkle_proof|verify_proof|zk_verify|"
    r"attestation_count|signatures\.len\s*\(\)\s*>=|threshold"
)

_SUCCESS_CHECK_RE = re.compile(
    r"require\s*\(\s*\w*(_success|_confirmed|_executed|_final)|"
    r"source_tx_status|tx_status\s*==|\.status\s*==\s*\w"
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

        if not _OBSERVER_GATE_RE.search(body_nc):
            continue
        if _QUORUM_OR_PROOF_RE.search(body_nc):
            continue
        if _SUCCESS_CHECK_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` is gated only by a single observer/"
                f"relayer role. No quorum / merkle proof / source-tx "
                f"success check. Rogue observer can mint or release funds "
                f"from fabricated inbound events. See Solodit #58631 "
                f"(ZetaChain Cross-Chain)."
            ),
        })
    return hits
