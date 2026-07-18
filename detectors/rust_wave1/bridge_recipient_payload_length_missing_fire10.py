"""
bridge_recipient_payload_length_missing_fire10.py

Flags Rust bridge handlers that decode the message recipient from untrusted
payload bytes and then burn, mint, release, or mark a message consumed before
proving both recipient-byte length and recipient/application domain binding.

This is a Fire10 lift of the confirmed recipient-length miss:
bridge-recipient-non-20-byte-payload-silently-burns. It adds bridge effect
gating and receiver-domain gating so the detector does not overlap the broad
Fire9 recipient-validation checks.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
)


_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_BRIDGE_CONTEXT_RE = re.compile(
    r"(?i)(bridge|cross_?chain|gateway|portal|router|payload|packet|"
    r"message|msg|receipt|proof|claim|finalize|deliver|receive|process|"
    r"release|mint|burn)"
)

_PAYLOAD_PARAM_RE = re.compile(
    r"(?is)\b(?:payload|message|msg|packet|body|raw|raw_payload|receipt)"
    r"\s*:\s*(?:&?\s*\[\s*u8\s*\]|Vec\s*<\s*u8\s*>|Bytes|Binary|"
    r"&\s*Vec\s*<\s*u8\s*>)"
)

_RECIPIENT_DECODE_RE = re.compile(
    r"(?is)("
    r"(?:let\s+(?:mut\s+)?(?:recipient|receiver|to|beneficiary)"
    r"(?:_bytes|_payload|_addr|_address)?\s*(?::[^=;\n]+)?=\s*&?"
    r"(?:payload|message|msg|packet|body|raw_payload|receipt)"
    r"(?:\s*\[|\.as_slice\s*\(|\.get\s*\())|"
    r"(?:recipient|receiver|to|beneficiary)(?:_bytes|_addr|_address)?"
    r"(?:\s*\[[^\]]+\])?\s*\.\s*copy_from_slice\s*\(\s*&?"
    r"(?:payload|message|msg|packet|body|raw_payload|receipt)\s*\[|"
    r"(?:Address|Recipient|Receiver|AccountId|H160)::"
    r"(?:from_slice|try_from|from_bytes)\s*\(\s*&?"
    r"(?:payload|message|msg|packet|body|raw_payload|receipt)|"
    r"decode_(?:recipient|receiver|address|to)\s*\(\s*&?"
    r"(?:payload|message|msg|packet|body|raw_payload|receipt)"
    r")"
)

_EFFECT_RE = re.compile(
    r"(?is)("
    r"\b(?:burn|burn_from|burn_tokens|burn_remote|_burn)\s*\(|"
    r"\.\s*(?:burn|burn_from|burn_tokens)\s*\(|"
    r"\b(?:mint|mint_to|mint_tokens|credit|credit_to|credit_account)"
    r"\s*\(|"
    r"\.\s*(?:mint|mint_to|credit|credit_to|credit_account)\s*\(|"
    r"\b(?:release|release_to|release_tokens|release_tokens_to|payout_to|"
    r"transfer_to|send_to)\s*\(|"
    r"\.\s*(?:release|release_to|release_tokens|transfer|send_to)\s*\(|"
    r"\b(?:mark_consumed|mark_processed|consume_message|set_consumed)"
    r"\s*\(|"
    r"\.\s*(?:insert|set|push)\s*\([^;\n]*(?:consumed|processed|spent|"
    r"seen|delivered)|"
    r"\b(?:consumed|processed|spent|seen|delivered)[A-Za-z0-9_]*\s*"
    r"(?:\.insert\s*\(|\.set\s*\(|\[)"
    r")"
)

_EXACT_LEN_GUARD_RE = re.compile(
    r"(?is)("
    r"(?:payload|message|msg|packet|body|raw_payload|receipt|recipient|"
    r"receiver|to|beneficiary)(?:_bytes|_payload|_addr|_address)?"
    r"(?:\s*\.\s*\w+)*\s*\.len\s*\(\s*\)\s*(?:==|!=)\s*20|"
    r"20\s*(?:==|!=)\s*(?:payload|message|msg|packet|body|raw_payload|"
    r"receipt|recipient|receiver|to|beneficiary)(?:_bytes|_payload|"
    r"_addr|_address)?(?:\s*\.\s*\w+)*\s*\.len\s*\(\s*\)|"
    r"validate_[A-Za-z0-9_]*(?:recipient|receiver|address|to)"
    r"[A-Za-z0-9_]*(?:len|length|twenty|20|exact)|"
    r"(?:recipient|receiver|address|to)[A-Za-z0-9_]*"
    r"try_into\s*\(\s*\)\s*\?|"
    r"<\s*\[\s*u8\s*;\s*20\s*\]\s*>::\s*try_from\s*\("
    r")"
)

_DOMAIN_GUARD_RE = re.compile(
    r"(?is)("
    r"(?:validate|check|ensure|assert|require)[A-Za-z0-9_!]*\s*\("
    r"[^;\n]*(?:recipient|receiver|application|app|destination|dest|"
    r"export|bridge)?[A-Za-z0-9_]*(?:domain|namespace|app_id|chain_id|"
    r"chain|eid)[^;\n]*(?:==|!=|allowed|expected|self\.|config\.)|"
    r"(?:recipient|receiver|application|app|destination|dest|export|"
    r"bridge)?[A-Za-z0-9_]*(?:domain|namespace|app_id|chain_id|chain|eid)"
    r"[^;\n]*(?:==|!=)[^;\n]*(?:expected|allowed|self\.|config\.|local)|"
    r"(?:validate|check|ensure)[A-Za-z0-9_]*(?:recipient|receiver|"
    r"application|app|destination|dest|export|bridge)?[A-Za-z0-9_]*"
    r"(?:domain|namespace|app_id|chain_id|chain|eid)|"
    r"(?:hash|digest|replay_key|message_key|receipt_key)[A-Za-z0-9_]*"
    r"\s*\([^;\n]*(?:recipient|receiver|application|app|destination|dest|"
    r"export|bridge)?[A-Za-z0-9_]*(?:domain|namespace|app_id|chain_id|"
    r"chain|eid)"
    r")"
)

_PRIMITIVE_FN_RE = re.compile(
    r"(?i)^(burn|mint|mint_to|release|release_to|transfer|send_to|"
    r"mark_consumed|mark_processed)$"
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub(_blank, text)


def _first_effect_index(body_text: str) -> int | None:
    match = _EFFECT_RE.search(body_text)
    return match.start() if match else None


def _has_bridge_context(name: str, fn_text: str) -> bool:
    return bool(_BRIDGE_CONTEXT_RE.search(name) or _BRIDGE_CONTEXT_RE.search(fn_text))


def _decodes_recipient_from_payload(fn_text: str, body_text: str) -> bool:
    if not _PAYLOAD_PARAM_RE.search(fn_text):
        return False
    return _RECIPIENT_DECODE_RE.search(body_text) is not None


def run(tree, source: bytes, filepath: str, *, engine=None):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        if _PRIMITIVE_FN_RE.match(name):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        fn_text = source[fn.start_byte:fn.end_byte].decode(
            "utf-8", errors="replace"
        )
        body_nc = _strip_strings(body_text_nocomment(body, source))

        if not _has_bridge_context(name, fn_text):
            continue
        if not _decodes_recipient_from_payload(fn_text, body_nc):
            continue

        effect_index = _first_effect_index(body_nc)
        if effect_index is None:
            continue

        before_effect = body_nc[:effect_index]
        missing: list[str] = []
        if not _EXACT_LEN_GUARD_RE.search(before_effect):
            missing.append("exact 20-byte recipient length")
        if not _DOMAIN_GUARD_RE.search(before_effect):
            missing.append("recipient/application domain binding")
        if not missing:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` decodes a bridge recipient from "
                    f"untrusted payload bytes and reaches a custody or "
                    f"message-consume effect before validating "
                    f"{' and '.join(missing)} "
                    f"(class: bridge-proof-domain-bypass / "
                    f"bridge-recipient-payload-length-missing-fire10)."
                ),
            }
        )

    return hits
