"""
r94_loop_sig_verify_message_hash_missing_nonce_replay.py

Flags pub fns that verify a signature over a message hash but never
increment / check a nonce (nor track used-sig / processed-messages) —
anyone can re-submit the same signature to re-drive the state
transition.

Source: Solodit #51938 (Halborn Analog Labs Gateway).
Class: sig-verify-message-hash-missing-nonce-replay (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(update_keys|updateKeys|"
    r"verify_message|verifyMessage|"
    r"execute_signed|executeSigned|"
    r"process_signed_op|relayed_call)"
)
_SIG_VERIFY_RE = re.compile(
    r"(verify_signature|verifySignature|"
    r"ecdsa_recover|ecrecover|_verify_sig|"
    r"ecdsa::recover|secp256k1::verify)"
)
_NONCE_USAGE_RE = re.compile(
    r"(nonce\s*\+=\s*1|"
    r"nonces\s*\[\s*\w+\s*\]\s*=|"
    r"require\s*\(\s*[\w\.]*nonce\s*==|"
    r"assert\s*!\s*\(\s*[\w\.]*nonce\s*==|"
    r"assert_eq\s*!\s*\(\s*[\w\.]*nonce|"
    r"nonces\.update|"
    r"[\w\.]*nonce\s*=\s*[\w\.]*nonce\s*\+\s*1|"
    fr"used\[\s*{IDENT}hash\s*\]\s*=\s*true|"
    r"used_sigs\.insert|"
    r"processed_messages\[)"
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
        if not _SIG_VERIFY_RE.search(body_nc):
            continue
        if _NONCE_USAGE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} verifies a signature over a message "
                f"hash but never uses / bumps a nonce (nor tracks "
                f"used-sig/processed-messages) — anyone can re-submit "
                f"the same signature to re-drive the state transition "
                f"(sig-verify-message-hash-missing-nonce-replay). "
                f"See Solodit #51938 (Halborn Analog Labs Gateway)."
            ),
        })
    return hits
