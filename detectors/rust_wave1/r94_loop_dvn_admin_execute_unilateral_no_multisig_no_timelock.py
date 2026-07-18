"""
r94_loop_dvn_admin_execute_unilateral_no_multisig_no_timelock.py

Flags DVN attestation endpoints (`execute`, `execute_attestation`,
`post_attestation`, `publish_attestation`, `commit_attestation`,
`emit_payload_verified`, etc.) that are gated by a single admin EOA
(`only_admin`, `only_role(ADMIN_ROLE)`, `require(msg.sender == admin)`)
with no multisig, no timelock, and no DVN signer quorum — compromise of
the admin key = full bridge compromise.

Source: Kelp rsETH exploit.
Class: dvn-admin-execute-unilateral-no-multisig-no-timelock (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(^execute$|execute_attestation|executeAttestation|"
    r"attest|admin_attest|post_attestation|postAttestation|"
    r"publish_attestation|publishAttestation|"
    r"commit_attestation|commitAttestation|"
    r"emit_payload_verified|emitPayloadVerified)"
)
_SINGLE_AUTH_RE = re.compile(
    r"(only_admin|onlyAdmin|"
    r"only_role\s*\(\s*ADMIN_ROLE|onlyRole\s*\(\s*ADMIN_ROLE|"
    r"require\s*\(\s*hasRole\s*\(\s*ADMIN_ROLE|"
    fr"require\s*\(\s*msg\.sender\s*==\s*{IDENT}admin)"
)
_SAFE_RE = re.compile(
    r"(multisig|multiSig|MultiSig|"
    r"timelock|TimeLock|TIMELOCK|"
    r"signer_quorum|signerQuorum|"
    r"schnorr_aggregated_sig|aggregated_sig|"
    r"dvn_signer_set|dvnSignerSet|"
    r"gnosis_safe|GnosisSafe|threshold_check|"
    fr"require\s*\(\s*{IDENT}signatures\.length\s*>=\s*{IDENT}threshold|"
    fr"require\s*\(\s*{IDENT}signature_count\s*>=\s*(2|3|4))"
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
        if not _SINGLE_AUTH_RE.search(body_nc):
            continue
        if _SAFE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} is a DVN attestation endpoint that "
                f"only requires a single admin EOA (no multisig, no "
                f"timelock, no signer quorum) — compromise of that EOA "
                f"= full bridge compromise "
                f"(dvn-admin-execute-unilateral-no-multisig-no-timelock). "
                f"Kelp rsETH $220M exploit 2026-04-18."
            ),
        })
    return hits
