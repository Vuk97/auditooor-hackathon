"""
r94_loop_permit2_intent_binding_missing.py

Flags fns that call Permit2 `permitTransferFrom` / `permitWitnessTransferFrom`
but construct the SignatureTransferDetails / permit struct with a
caller-controlled recipient and do NOT include a witness hash binding
the intended recipient / function.

Source: Solodit #54669 (Cantina Sablier SablierV2ProxyTarget).
Class: permit2-intent-binding-missing (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(r"(?i)(permit_transfer|batch_transfer_with_permit|proxy_permit|batch_create|permit2_execute)")
_CALLS_PERMIT2_RE = re.compile(
    fr"permit_?[Tt]ransfer[Ff]rom|permit_?[Ww]itness[Tt]ransfer|permit2\.{IDENT}transfer|"
    r"ISignatureTransfer"
)
_INTENT_BIND_RE = re.compile(
    r"witness\s*\(|witness_hash|witness_type|bound_intent|intent_digest|"
    r"recipient_in_witness|tag_recipient"
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
        if not _CALLS_PERMIT2_RE.search(body_nc):
            continue
        if _INTENT_BIND_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` calls Permit2 transferFrom without "
                f"a witness hash binding the intended recipient / "
                f"function — frontrunner extracts permit and redirects "
                f"funds (permit2-intent-binding-missing). See Solodit "
                f"#54669 (Sablier)."
            ),
        })
    return hits
