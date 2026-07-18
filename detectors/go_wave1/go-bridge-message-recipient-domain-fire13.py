"""
go-bridge-message-recipient-domain-fire13.py

Detects Go bridge message handlers that release, mint, credit, dispatch, or
settle value to a message, payload, event, or proof recipient before binding
that recipient to a canonical route/request recipient or to receiver-chain /
receiver-domain context.

This is a narrow companion for the Fire13 recall gap:
`go-bridge-message-recipient-validation-missing-positive` was measured as a
bridge-proof-domain-bypass miss because the Go Wave1 registry had no same-class
detector for message recipient domain binding. The detector deliberately
requires a bridge/message handler, a supplied recipient sink, and either a
canonical recipient or route/domain context.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-bridge-message-recipient-domain-fire13"

_HANDLER_NAME_RE = re.compile(
    r"(Bridge|Message|Msg|Relay|Inbound|Outbound|Packet|Proof|Payload"
    r"|Transfer|Credit|Settle|Settlement|Release|Mint|Claim|Finalize"
    r"|Complete|Receive|Deliver|Dispatch)",
    re.IGNORECASE,
)

_BRIDGE_BODY_RE = re.compile(
    r"(bridge|message|relay|packet|payload|proof|recipient|receiver"
    r"|domain|chain|route|canonical|sink|settle|settlement|credit"
    r"|transfer|mint|release|dispatch)",
    re.IGNORECASE,
)

_RECIPIENT_FIELD = (
    r"(?:Recipient|Receiver|To|ToAddress|Destination|DestinationAddress"
    r"|Target|TargetAddress|Beneficiary|Account|Address)"
)

_DOMAIN_FIELD = (
    r"(?:ReceiverDomain|RecipientDomain|DestinationDomain|DestDomain"
    r"|TargetDomain|SourceDomain|RemoteDomain|HomeDomain|Domain"
    r"|ReceiverChain|RecipientChain|DestinationChain|DestChain"
    r"|TargetChain|SourceChain|ChainID|ChainId|Chain|EID|Eid"
    r"|EndpointID|EndpointId|DstEID|DstEid|RouteID|RouteId|Lane"
    r"|LaneID|LaneId|ChannelID|ChannelId)"
)

_SUPPLIED_PREFIX = (
    r"(?:memo|payload|event|evt|parsed|body|packet|message|envelope"
    r"|proof|claim|receipt|attestation|vaa|bridgeMsg|bridgeMessage"
    r"|inbound|outbound)"
)

_CANONICAL_PREFIX = (
    r"(?:msg|request|req|route|canonical|sink|settlement|transfer"
    r"|claim|deposit|order|expected|verified|proof|commitment|params"
    r"|configured)"
)

_SUPPLIED_RECIPIENT_RE = re.compile(
    r"\b" + _SUPPLIED_PREFIX + r"\." + _RECIPIENT_FIELD + r"\b"
)

_CANONICAL_RECIPIENT_RE = re.compile(
    r"\b" + _CANONICAL_PREFIX + r"\." + _RECIPIENT_FIELD + r"\b"
    r"|\b(?:canonicalRecipient|expectedRecipient|sinkRecipient"
    r"|routeRecipient|verifiedRecipient|proofRecipient"
    r"|canonicalReceiver|expectedReceiver|sinkReceiver"
    r"|routeReceiver|verifiedReceiver|proofReceiver"
    r"|canonicalSink|expectedSink|settlementRecipient)\b"
)

_DOMAIN_RE = re.compile(
    r"\b(?:" + _SUPPLIED_PREFIX + r"|" + _CANONICAL_PREFIX + r"|k)\."
    + _DOMAIN_FIELD
    + r"\b"
    r"|\b(?:receiverDomain|recipientDomain|destinationDomain|destDomain"
    r"|targetDomain|sourceDomain|remoteDomain|homeDomain|localDomain"
    r"|expectedDomain|canonicalDomain|routeDomain|configuredDomain"
    r"|receiverChain|recipientChain|destinationChain|sourceChain"
    r"|localChain|expectedChain|canonicalChain|routeChain"
    r"|configuredChain|dstEID|dstEid|expectedEID|routeID|laneID)\b",
    re.IGNORECASE,
)

_ASSIGN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?::=|=)\s*([^;\n]+)")

_SINK_CALL_PREFIX_RE = re.compile(
    r"\b(?P<name>SendCoinsFromModuleToAccount|SendCoins|SendAsset"
    r"|Transfer|SafeTransfer|TransferFrom|MintTo|Mint|BridgeMint"
    r"|Credit|CreditAccount|CreditRecipient|Settle|SettleTo"
    r"|SettleTransfer|Payout|PayoutTo|Release|ReleaseTo"
    r"|CompleteTransfer|FinalizeTransfer|Dispatch|DispatchMessage"
    r"|RouteMessage|ExecuteMessage|Execute|CallReceiver|Deliver"
    r"|DeliverMessage|SendPacket)\s*\(",
    re.IGNORECASE,
)

_RECIPIENT_ARG_INDEXES = {
    "sendcoinsfrommoduletoaccount": (2,),
    "sendcoins": (2,),
    "sendasset": (1, 2),
    "transfer": (0, 1, 2),
    "safetransfer": (0, 1, 2),
    "transferfrom": (1, 2),
    "mintto": (0, 1),
    "mint": (0, 1),
    "bridgemint": (0, 1),
    "credit": (0, 1, 2),
    "creditaccount": (0, 1, 2),
    "creditrecipient": (0, 1, 2),
    "settle": (0, 1, 2),
    "settleto": (0, 1, 2),
    "settletransfer": (0, 1, 2),
    "payout": (0, 1),
    "payoutto": (0, 1),
    "release": (0, 1, 2),
    "releaseto": (0, 1, 2),
    "completetransfer": (0, 1, 2),
    "finalizetransfer": (0, 1, 2),
    "dispatch": (0, 1, 2),
    "dispatchmessage": (0, 1, 2),
    "routemessage": (0, 1, 2),
    "executemessage": (0, 1, 2),
    "execute": (0, 1, 2),
    "callreceiver": (0, 1),
    "deliver": (0, 1, 2),
    "delivermessage": (0, 1, 2),
    "sendpacket": (0, 1, 2),
}

_BINDING_HELPER_RE = re.compile(
    r"(Validate|Ensure|Assert|Bind|Check|Require|Confirm|Verify)"
    r"[A-Za-z_]*(Recipient|Receiver|Domain|Chain|Route|Lane|EID)"
    r"[A-Za-z_]*(Binding|Match|Matches|Bound|Scope|Scoped)?\s*\(",
    re.IGNORECASE,
)

_TRUSTED_RECIPIENT_RE = re.compile(
    r"(expected|canonical|verified|proof|claim|route|settlement|commitment"
    r"|public|bound|configured|params|sink)",
    re.IGNORECASE,
)

_TRUSTED_DOMAIN_RE = re.compile(
    r"(expected|canonical|verified|proof|claim|route|commitment|public"
    r"|bound|configured|params|localDomain|homeDomain|localChain"
    r"|homeChain|chainConfig|expectedDomain|canonicalDomain"
    r"|configuredDomain|expectedChain|canonicalChain|configuredChain"
    r"|expectedEID|canonicalEID)",
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
    return bool(_SUPPLIED_RECIPIENT_RE.search(expr)) or _mentions_any(expr, aliases)


def _is_canonical_expr(expr: str, aliases: set[str]) -> bool:
    return bool(_CANONICAL_RECIPIENT_RE.search(expr)) or _mentions_any(expr, aliases)


def _is_domain_expr(expr: str, aliases: set[str]) -> bool:
    return bool(_DOMAIN_RE.search(expr)) or _mentions_any(expr, aliases)


def _collect_aliases(body_text: str) -> tuple[set[str], set[str], set[str]]:
    supplied_aliases: set[str] = set()
    canonical_aliases: set[str] = set()
    domain_aliases: set[str] = set()

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

        if _is_domain_expr(rhs, domain_aliases):
            domain_aliases.add(lhs)
        else:
            domain_aliases.discard(lhs)

    return supplied_aliases, canonical_aliases, domain_aliases


def _terms_for(body_text: str, aliases: set[str], direct_re: re.Pattern[str]) -> set[str]:
    terms = set(aliases)
    terms.update(match.group(0) for match in direct_re.finditer(body_text))
    return terms


def _has_pairwise_comparison(left_terms: set[str], right_terms: set[str], text: str) -> bool:
    for left in left_terms:
        left_pat = _term_pattern(left)
        for right in right_terms:
            right_pat = _term_pattern(right)
            if re.search(left_pat + r"\s*(?:!=|==)\s*" + right_pat, text, re.S):
                return True
            if re.search(right_pat + r"\s*(?:!=|==)\s*" + left_pat, text, re.S):
                return True
            if re.search(left_pat + r"\.Equal\s*\(\s*" + right_pat, text, re.S):
                return True
            if re.search(right_pat + r"\.Equal\s*\(\s*" + left_pat, text, re.S):
                return True
            if (
                "bytes.Equal(" in text
                and _mentions_any(text, {left})
                and _mentions_any(text, {right})
            ):
                return True
    return False


def _has_trusted_comparison(
    text: str,
    terms: set[str],
    trusted_re: re.Pattern[str],
) -> bool:
    for line in text.splitlines():
        if not re.search(r"(?:!=|==|\.Equal\s*\(|\.Equals\s*\(|bytes\.Equal\s*\()", line):
            continue
        if _mentions_any(line, terms) and trusted_re.search(line):
            return True
    return False


def _has_binding_guard(
    body_text: str,
    supplied_terms: set[str],
    canonical_terms: set[str],
    domain_terms: set[str],
) -> bool:
    if _BINDING_HELPER_RE.search(body_text):
        return True

    recipient_bound = True
    if canonical_terms:
        recipient_bound = _has_pairwise_comparison(
            supplied_terms,
            canonical_terms,
            body_text,
        ) or _has_trusted_comparison(body_text, supplied_terms, _TRUSTED_RECIPIENT_RE)

    domain_bound = True
    if domain_terms:
        domain_bound = _has_trusted_comparison(
            body_text,
            domain_terms,
            _TRUSTED_DOMAIN_RE,
        )

    return recipient_bound and domain_bound


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

        supplied_aliases, canonical_aliases, domain_aliases = _collect_aliases(body_text)
        supplied_terms = _terms_for(body_text, supplied_aliases, _SUPPLIED_RECIPIENT_RE)
        canonical_terms = _terms_for(body_text, canonical_aliases, _CANONICAL_RECIPIENT_RE)
        domain_terms = _terms_for(body_text, domain_aliases, _DOMAIN_RE)

        if not supplied_terms:
            continue
        if not (canonical_terms or domain_terms):
            continue
        if not _pays_supplied_recipient(body_text, supplied_terms):
            continue
        if _has_binding_guard(body_text, supplied_terms, canonical_terms, domain_terms):
            continue

        hits.append(
            {
                "severity": "high",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` routes bridge value to a message, payload, event, "
                    f"or proof recipient without binding it to the canonical "
                    f"recipient or receiver domain. Bridge message handlers "
                    f"should compare recipient and route/domain context before "
                    f"mint, release, credit, dispatch, or settlement. "
                    f"(class: bridge-proof-domain-bypass)"
                ),
            }
        )

    return hits
