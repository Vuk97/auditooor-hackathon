"""
r94_loop_bridge_receive_library_quorum_single_signer_is_sole_gate.py

Flags bridge receive-library verify fns that accept a packet once the
configured DVN/signer quorum is met but enforce no minimum-quorum-size
>= 2 or secondary attestation — when required-count is 1, a single DVN
compromise bypasses the entire receive library.

Source: Kelp rsETH exploit (2026-04-18, banteg).
Class: bridge-receive-library-quorum-single-signer-is-sole-gate (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(verify|verify_packet|verifyPacket|"
    r"commit_verification|commitVerification|"
    r"_verify|assert_verified|require_verified)"
)
_QUORUM_READ_RE = re.compile(
    r"(required_dvn_count|requiredDVNCount|"
    r"required_signers|requiredSigners|"
    r"quorum_size|quorumSize|N_OF_M|n_of_m)"
)
_QUORUM_CHECK_RE = re.compile(
    fr"(>=\s*{IDENT}(required_dvn_count|requiredDVNCount|quorum_size|quorumSize)|"
    fr"signatures\.len\s*\(\s*\)\s*>=\s*{IDENT}(quorum|required)|"
    fr"num_valid\s*>=\s*{IDENT}required)"
)
_SINGLE_GATE_OK_RE = re.compile(
    fr"(require\s*\(\s*{IDENT}(required_dvn_count|requiredDVNCount)\s*>=?\s*2|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}(required_dvn_count|requiredDVNCount)\s*>=?\s*2|"
    r"OptionalDVN|optional_dvn_threshold\s*(>=?\s*[1-9]|\s*[>=<]\s*0\s*,)|"
    r"multi_sig_gate|multiSigGate|"
    r"attester_pool\.len\s*\(\s*\)\s*>=?\s*3|"
    r"redundant_attestation_check)"
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
        if not _QUORUM_READ_RE.search(body_nc):
            continue
        if not _QUORUM_CHECK_RE.search(body_nc):
            continue
        if _SINGLE_GATE_OK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} accepts a packet once the configured "
                f"DVN/signer quorum is met, but enforces no "
                f"minimum-quorum-size >= 2 or secondary attestation — "
                f"when required-count is 1, a single DVN compromise "
                f"bypasses the entire receive library "
                f"(bridge-receive-library-quorum-single-signer-is-sole-gate). "
                f"Kelp rsETH $220M exploit 2026-04-18."
            ),
        })
    return hits
