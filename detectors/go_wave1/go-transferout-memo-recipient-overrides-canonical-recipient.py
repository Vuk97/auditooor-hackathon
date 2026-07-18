"""
go-transferout-memo-recipient-overrides-canonical-recipient.py

Detects narrow Go transfer-out handlers that route payout to `memo.Recipient`
even though the canonical destination is already present in `msg.ToAddress`,
without any equality check binding the two values together.

This shape is intentionally narrow. It only fires when a function:
1. Looks like a transfer-out or outbound handler.
2. References both `memo.Recipient` and `msg.ToAddress`.
3. Either sends directly to `memo.Recipient` or first assigns it to a local
   recipient variable and then pays that local variable.
4. Lacks an explicit equality check or named binding helper.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-transferout-memo-recipient-overrides-canonical-recipient"

_HANDLER_NAME_RE = re.compile(
    r"(TransferOut|Transferout|Outbound|HandleTransfer|HandleMemo|RouteTransfer)",
    re.IGNORECASE,
)

_BRIDGE_BODY_RE = re.compile(
    r"(memo|transferOut|outbound|router|bridge|vault|msg\.ToAddress)",
    re.IGNORECASE,
)

_MEMO_RECIPIENT_RE = re.compile(r"\bmemo\.Recipient\b")
_CANONICAL_RECIPIENT_RE = re.compile(r"\bmsg\.ToAddress\b")
_MEMO_ALIAS_ASSIGN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?::=|=)\s*memo\.Recipient\b")
_ASSIGN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?::=|=)\s*([^;\n]+)")
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_SINK_CALL_PREFIX_RE = re.compile(
    r"\b(?P<name>SendCoinsFromModuleToAccount|SendCoins|Transfer|payoutTo|SendAsset|Dispatch)\s*\(",
    re.IGNORECASE,
)

_BINDING_GUARD_RE = re.compile(
    r"(ValidateMemoRecipientBinding\s*\(|EnsureMemoRecipientMatches\s*\("
    r"|ValidateRecipientBinding\s*\(|AssertRecipientMatches\s*\("
    r"|if\s+[^{}]*(?:memo\.Recipient\s*(?:!=|==)\s*msg\.ToAddress"
    r"|msg\.ToAddress\s*(?:!=|==)\s*memo\.Recipient))",
    re.DOTALL,
)

_RECIPIENT_ARG_INDEXES = {
    "sendcoinsfrommoduletoaccount": (2,),
    "sendcoins": (2,),
    "transfer": (0, 2),
    "payoutto": (0,),
    "sendasset": (1, 2),
    "dispatch": (1, 2),
}


def _blank_comment(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank_comment, src)
    return re.sub(r"/\*.*?\*/", _blank_comment, src, flags=re.S)


def _strip_comments_and_strings(src: str) -> str:
    src = _strip_comments(src)
    return _STRING_RE.sub(_blank_comment, src)


def _split_call_args(call_text: str) -> list[str]:
    start = call_text.find("(")
    end = call_text.rfind(")")
    if start < 0 or end <= start:
        return []
    args_text = call_text[start + 1 : end]
    args: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in args_text:
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth > 0:
            depth -= 1
    if current or args_text.strip():
        args.append("".join(current).strip())
    return args


def _pays_memo_recipient(body_text: str) -> bool:
    aliases: set[str] = set()
    sink_call: list[str] = []
    sink_depth = 0

    def is_memo_derived(rhs: str) -> bool:
        if "memo.Recipient" in rhs:
            return True
        return any(re.search(rf"\b{re.escape(alias)}\b", rhs) for alias in aliases)

    def mentions_memo_target(text: str) -> bool:
        if "memo.Recipient" in text:
            return True
        return any(re.search(rf"\b{re.escape(alias)}\b", text) for alias in aliases)

    def call_pays_memo_target(call_text: str) -> bool:
        match = _SINK_CALL_PREFIX_RE.search(call_text)
        if not match:
            return False
        indexes = _RECIPIENT_ARG_INDEXES.get(match.group("name").lower(), ())
        args = _split_call_args(call_text)
        return any(
            idx < len(args) and mentions_memo_target(args[idx])
            for idx in indexes
        )

    for line in body_text.splitlines():
        assign = _ASSIGN_RE.search(line)
        if assign:
            lhs = assign.group(1)
            rhs = assign.group(2)
            if is_memo_derived(rhs):
                aliases.add(lhs)
            elif lhs in aliases:
                aliases.discard(lhs)

        if sink_call:
            sink_call.append(line)
            sink_depth += line.count("(") - line.count(")")
            if sink_depth <= 0:
                if call_pays_memo_target("\n".join(sink_call)):
                    return True
                sink_call = []
            continue

        if not _SINK_CALL_PREFIX_RE.search(line):
            continue
        sink_call = [line]
        sink_depth = line.count("(") - line.count(")")
        if sink_depth <= 0:
            if call_pays_memo_target(line):
                return True
            sink_call = []
    return False


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
        if not _MEMO_RECIPIENT_RE.search(body_text):
            continue
        if not _CANONICAL_RECIPIENT_RE.search(fn_text_clean):
            continue
        if not _pays_memo_recipient(body_text):
            continue
        if _BINDING_GUARD_RE.search(body_text):
            continue

        hits.append(
            {
                "severity": "high",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` pays a memo-derived recipient even though "
                    f"`msg.ToAddress` already carries the canonical transfer-out "
                    f"recipient, and no equality check binds the two values. "
                    f"(class: missing-recipient-validation)"
                ),
            }
        )

    return hits
