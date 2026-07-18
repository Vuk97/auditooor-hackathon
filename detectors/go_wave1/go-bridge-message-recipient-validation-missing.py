"""
go-bridge-message-recipient-validation-missing.py

Detects Go bridge, relay, and settlement handlers where a user supplied memo,
event, or payload recipient is used as the value sink while a canonical message
recipient or sink is present but not equality-bound to that supplied recipient.

This detector is intentionally narrower than a generic transfer validator. It
only fires when a function:
1. Looks like a bridge, message, relay, transfer, credit, or settlement path.
2. References a user supplied memo, event, or payload recipient.
3. References a canonical message, request, route, settlement, or sink
   recipient in the same function.
4. Sends, credits, settles, releases, or dispatches value to the supplied
   recipient, directly or through a local alias.
5. Lacks an explicit equality check or named binding helper.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-bridge-message-recipient-validation-missing"

_HANDLER_NAME_RE = re.compile(
    r"(Bridge|Message|Msg|Relay|Inbound|Outbound|Packet|Memo|Payload|Event"
    r"|Transfer|Credit|Settle|Settlement|Release|Claim|Finalize|Fulfill)",
    re.IGNORECASE,
)

_BRIDGE_BODY_RE = re.compile(
    r"(bridge|message|relay|packet|memo|payload|event|recipient|settle"
    r"|settlement|credit|transfer|canonical|sink)",
    re.IGNORECASE,
)

_RECIPIENT_FIELD = r"(?:Recipient|Receiver|To|ToAddress|Destination|Beneficiary|Account|Address)"

_SUPPLIED_RECIPIENT_RE = re.compile(
    r"\b(?:memo|payload|event|evt|parsed|body|packet|message|envelope)"
    r"\." + _RECIPIENT_FIELD + r"\b"
)

_CANONICAL_RECIPIENT_RE = re.compile(
    r"\b(?:msg|request|req|route|canonical|sink|settlement|transfer|claim"
    r"|deposit|order|expected)\." + _RECIPIENT_FIELD + r"\b"
    r"|\b(?:canonicalRecipient|expectedRecipient|sinkRecipient"
    r"|canonicalReceiver|expectedReceiver|sinkReceiver"
    r"|canonicalSink|expectedSink|settlementRecipient)\b"
)

_ASSIGN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?::=|=)\s*([^;\n]+)")

_SINK_CALL_PREFIX_RE = re.compile(
    r"\b(?P<name>SendCoinsFromModuleToAccount|SendCoins|Transfer"
    r"|Credit|CreditAccount|CreditRecipient|Settle|SettleTo"
    r"|SettleTransfer|payoutTo|Payout|SendAsset|Dispatch|Release"
    r"|ReleaseTo|MintTo|FinalizeTransfer|CompleteTransfer)\s*\(",
    re.IGNORECASE,
)

_RECIPIENT_ARG_INDEXES = {
    "sendcoinsfrommoduletoaccount": (2,),
    "sendcoins": (2,),
    "transfer": (0, 1, 2),
    "credit": (0, 1, 2),
    "creditaccount": (0, 1, 2),
    "creditrecipient": (0, 1, 2),
    "settle": (0, 1, 2),
    "settleto": (0, 1, 2),
    "settletransfer": (0, 1, 2),
    "payoutto": (0, 1),
    "payout": (0, 1),
    "sendasset": (1, 2),
    "dispatch": (1, 2),
    "release": (0, 1, 2),
    "releaseto": (0, 1, 2),
    "mintto": (0, 1),
    "finalizetransfer": (0, 1, 2),
    "completetransfer": (0, 1, 2),
}

_BINDING_HELPER_RE = re.compile(
    r"(Validate(?:Memo|Payload|Event|Message)?Recipient(?:Binding|Match|Matches)?\s*\("
    r"|Ensure(?:Memo|Payload|Event|Message)?RecipientMatches\s*\("
    r"|ValidateRecipientBinding\s*\(|AssertRecipientMatches\s*\("
    r"|RecipientMatches\s*\(|EqualRecipient\s*\()",
    re.IGNORECASE,
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


def _term_pattern(term: str) -> str:
    return r"(?<![\w.])" + re.escape(term) + r"(?![\w.])"


def _mentions_any(text: str, terms: set[str]) -> bool:
    return any(re.search(_term_pattern(term), text) for term in terms)


def _is_supplied_expr(expr: str, aliases: set[str]) -> bool:
    if _SUPPLIED_RECIPIENT_RE.search(expr):
        return True
    return _mentions_any(expr, aliases)


def _is_canonical_expr(expr: str, aliases: set[str]) -> bool:
    if _CANONICAL_RECIPIENT_RE.search(expr):
        return True
    return _mentions_any(expr, aliases)


def _collect_aliases(body_text: str) -> tuple[set[str], set[str]]:
    supplied_aliases: set[str] = set()
    canonical_aliases: set[str] = set()

    for line in body_text.splitlines():
        assign = _ASSIGN_RE.search(line)
        if not assign:
            continue
        lhs = assign.group(1)
        rhs = assign.group(2)
        if _is_supplied_expr(rhs, supplied_aliases):
            supplied_aliases.add(lhs)
            canonical_aliases.discard(lhs)
        elif _is_canonical_expr(rhs, canonical_aliases):
            canonical_aliases.add(lhs)
            supplied_aliases.discard(lhs)
        else:
            supplied_aliases.discard(lhs)
            canonical_aliases.discard(lhs)

    return supplied_aliases, canonical_aliases


def _terms_for(body_text: str, aliases: set[str], direct_re: re.Pattern[str]) -> set[str]:
    terms = set(aliases)
    terms.update(match.group(0) for match in direct_re.finditer(body_text))
    return terms


def _has_binding_guard(
    body_text: str,
    supplied_terms: set[str],
    canonical_terms: set[str],
) -> bool:
    if _BINDING_HELPER_RE.search(body_text):
        return True

    for supplied in supplied_terms:
        supplied_pat = _term_pattern(supplied)
        for canonical in canonical_terms:
            canonical_pat = _term_pattern(canonical)
            if re.search(
                supplied_pat + r"\s*(?:!=|==)\s*" + canonical_pat,
                body_text,
                re.S,
            ):
                return True
            if re.search(
                canonical_pat + r"\s*(?:!=|==)\s*" + supplied_pat,
                body_text,
                re.S,
            ):
                return True
            if re.search(
                supplied_pat + r"\.Equal\s*\(\s*" + canonical_pat,
                body_text,
                re.S,
            ):
                return True
            if re.search(
                canonical_pat + r"\.Equal\s*\(\s*" + supplied_pat,
                body_text,
                re.S,
            ):
                return True
            if (
                "bytes.Equal(" in body_text
                and _mentions_any(body_text, {supplied})
                and _mentions_any(body_text, {canonical})
            ):
                return True
    return False


def _call_pays_supplied_recipient(call_text: str, supplied_terms: set[str]) -> bool:
    match = _SINK_CALL_PREFIX_RE.search(call_text)
    if not match:
        return False
    indexes = _RECIPIENT_ARG_INDEXES.get(match.group("name").lower(), ())
    args = _split_call_args(call_text)
    return any(idx < len(args) and _mentions_any(args[idx], supplied_terms) for idx in indexes)


def _pays_supplied_recipient(body_text: str, supplied_terms: set[str]) -> bool:
    sink_call: list[str] = []
    sink_depth = 0

    for line in body_text.splitlines():
        if sink_call:
            sink_call.append(line)
            sink_depth += line.count("(") - line.count(")")
            if sink_depth <= 0:
                if _call_pays_supplied_recipient("\n".join(sink_call), supplied_terms):
                    return True
                sink_call = []
            continue

        if not _SINK_CALL_PREFIX_RE.search(line):
            continue
        sink_call = [line]
        sink_depth = line.count("(") - line.count(")")
        if sink_depth <= 0:
            if _call_pays_supplied_recipient(line, supplied_terms):
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

        supplied_aliases, canonical_aliases = _collect_aliases(body_text)
        supplied_terms = _terms_for(body_text, supplied_aliases, _SUPPLIED_RECIPIENT_RE)
        canonical_terms = _terms_for(body_text, canonical_aliases, _CANONICAL_RECIPIENT_RE)

        if not supplied_terms:
            continue
        if not canonical_terms:
            continue
        if not _pays_supplied_recipient(body_text, supplied_terms):
            continue
        if _has_binding_guard(body_text, supplied_terms, canonical_terms):
            continue

        hits.append(
            {
                "severity": "high",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` routes value to a memo, event, or payload recipient "
                    f"without equality-binding it to the canonical recipient or "
                    f"sink. Bridge message handlers should compare user supplied "
                    f"recipients against the canonical sink before transfer, "
                    f"credit, or settlement. (class: missing-recipient-validation)"
                ),
            }
        )

    return hits
