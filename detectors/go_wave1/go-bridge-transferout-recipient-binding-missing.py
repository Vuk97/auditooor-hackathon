"""
go-bridge-transferout-recipient-binding-missing.py

Detects Go bridge/router transfer-out handlers that derive the payout recipient
from a parsed memo/payload object and execute the transfer without binding that
derived recipient back to the canonical route/request recipient field.

Confirmed corpus anchor:
- THORChain-style router message-binding mismatch
  (`bridge-incident:thorchain-2021-07:c4e14a02ed01`, tier-2 verified archive)

This is intentionally narrow. It only fires when a function:
1. Looks like a transfer-out / outbound bridge handler.
2. References both a payload-derived recipient and a canonical request/tx
   recipient.
3. Sends value to the payload-derived recipient.
4. Lacks an explicit recipient-binding check.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-bridge-transferout-recipient-binding-missing"

_HANDLER_NAME_RE = re.compile(
    r"(TransferOut|Transferout|Outbound|HandleTransfer|HandleMemo|RouteTransfer)",
    re.IGNORECASE,
)

_BRIDGE_BODY_RE = re.compile(
    r"(memo|payload|outbound|transferOut|router|bridge|vault|observedTx|tx\.ToAddress)",
    re.IGNORECASE,
)

_PAYLOAD_RECIPIENT_RE = re.compile(
    r"\b(?:memo|payload|parsed|transferOut|outbound)\.(?:Recipient|ToAddress|To)\b"
)

_CANONICAL_RECIPIENT_RE = re.compile(
    r"\b(?:msg|request|req|route|tx|observedTx)\.(?:Recipient|ToAddress|To)\b"
)

_PAYLOAD_SEND_RE = re.compile(
    r"(?:SendCoinsFromModuleToAccount|SendCoins|Transfer|payoutTo|SendAsset|Dispatch)\s*\("
    r"[^\n]*\b(?:memo|payload|parsed|transferOut|outbound)\.(?:Recipient|ToAddress|To)\b",
    re.IGNORECASE,
)

_BINDING_GUARD_RE = re.compile(
    r"(ValidateRecipientBinding\s*\(|ValidateTransferOutRecipient\s*\("
    r"|ExpectedRecipient\s*\(|AssertRecipientMatches\s*\("
    r"|if\s+[^{}\n]*(?:memo|payload|parsed|transferOut|outbound)\.(?:Recipient|ToAddress|To)\s*!=\s*"
    r"(?:msg|request|req|route|tx|observedTx)\.(?:Recipient|ToAddress|To)"
    r"|if\s+[^{}\n]*(?:msg|request|req|route|tx|observedTx)\.(?:Recipient|ToAddress|To)\s*!=\s*"
    r"(?:memo|payload|parsed|transferOut|outbound)\.(?:Recipient|ToAddress|To))"
)
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def _blank_comment(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank_comment, src)
    return re.sub(r"/\*.*?\*/", _blank_comment, src, flags=re.S)


def _strip_comments_and_strings(src: str) -> str:
    src = _strip_comments(src)
    return _STRING_RE.sub(_blank_comment, src)


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue

        fn_text = engine.text(fn)
        body_text = _strip_comments_and_strings(engine.text(body))
        fn_text_clean = _strip_comments_and_strings(fn_text)

        if not (_HANDLER_NAME_RE.search(name) or _BRIDGE_BODY_RE.search(fn_text_clean)):
            continue
        if not _PAYLOAD_RECIPIENT_RE.search(body_text):
            continue
        if not _CANONICAL_RECIPIENT_RE.search(fn_text_clean):
            continue
        if not _PAYLOAD_SEND_RE.search(body_text):
            continue
        if _BINDING_GUARD_RE.search(body_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"`{name}` pays a payload-derived recipient without binding it "
                f"to the canonical transfer-out recipient. Bridge/router "
                f"handlers should compare memo/payload recipients against the "
                f"request or observed-tx recipient before sending funds. "
                f"(class: missing-recipient-validation)"
            ),
        })

    return hits
