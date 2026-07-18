"""
go-bridge-domain-or-recipient-binding-fire19.py

Fire19 Go lift for confirmed bridge proof domain bypass coverage.

Confirmed local corpus anchor:
- legacy:dydx-hunt-iter-1_dydx-hunt-c3-bridge-proof-domain-verdict.md:05abcd553b7f
  target_language=go, attack_class=bridge-proof-domain-bypass,
  verification_tier=tier-2-verified-public-archive, function shape
  RunBridgeDaemonTaskLoop.

Detects bridge daemon or relay handlers that verify or accept a proof/message,
then forward value to a supplied event/message recipient while route, expected
recipient, chain, or domain context exists but is not bound into the proof key
or checked before the sink call.

This is recall-oriented detector evidence only. A hit is not a filing verdict.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-bridge-domain-or-recipient-binding-fire19"

_HANDLER_NAME_RE = re.compile(
    r"(Bridge|Daemon|Relayer|Relay|Proof|Message|Msg|Receipt|Event|Packet"
    r"|Withdrawal|Withdraw|Claim|Finalize|Complete|Settle|Credit|Release"
    r"|RunBridgeDaemonTaskLoop)",
    re.IGNORECASE,
)

_BRIDGE_CONTEXT_RE = re.compile(
    r"(bridge|daemon|relayer|relay|proof|merkle|message|packet|receipt"
    r"|event|withdrawal|recipient|receiver|route|domain|chain|sourceChain"
    r"|destinationChain|bridgeDomain|lane|channel|emitter|namespace)",
    re.IGNORECASE,
)

_VERIFY_CALL_PREFIX_RE = re.compile(
    r"\b(?P<name>Verify(?:Bridge)?(?:Proof|Message|Receipt|Event)?"
    r"|Validate(?:Bridge)?(?:Proof|Message|Receipt|Event)?"
    r"|Accept(?:Bridge)?(?:Proof|Message|Receipt|Event)?"
    r"|Consume(?:Bridge)?(?:Proof|Message|Receipt|Event)?)\s*\(",
    re.IGNORECASE,
)

_SINK_CALL_PREFIX_RE = re.compile(
    r"\b(?P<name>SendCoinsFromModuleToAccount|SendCoins|SendAsset"
    r"|Transfer|TransferTo|Credit|CreditAccount|CreditRecipient"
    r"|CreditMessage|Settle|SettleTo|SettleTransfer|Payout|PayoutTo"
    r"|Release|ReleaseTo|Mint|MintTo|BridgeMint|ForwardValue"
    r"|CompleteTransfer|FinalizeTransfer|Dispatch|DispatchMessage"
    r"|Deliver|DeliverMessage)\s*\(",
    re.IGNORECASE,
)

_RECIPIENT_ARG_INDEXES = {
    "sendcoinsfrommoduletoaccount": (2,),
    "sendcoins": (2,),
    "sendasset": (1, 2),
    "transfer": (0, 1, 2),
    "transferto": (0, 1, 2),
    "credit": (0, 1, 2),
    "creditaccount": (0, 1, 2),
    "creditrecipient": (0, 1, 2),
    "creditmessage": (0, 1, 2),
    "settle": (0, 1, 2),
    "settleto": (0, 1, 2),
    "settletransfer": (0, 1, 2),
    "payout": (0, 1),
    "payoutto": (0, 1),
    "release": (0, 1, 2),
    "releaseto": (0, 1, 2),
    "mint": (0, 1),
    "mintto": (0, 1),
    "bridgemint": (0, 1),
    "forwardvalue": (0, 1),
    "completetransfer": (0, 1, 2),
    "finalizetransfer": (0, 1, 2),
    "dispatch": (0, 1, 2),
    "dispatchmessage": (0, 1, 2),
    "deliver": (0, 1, 2),
    "delivermessage": (0, 1, 2),
}

_ASSIGN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?::=|=)\s*([^;\n]+)")

_SUPPLIED_PREFIX = (
    r"(?:event|evt|message|msg|payload|packet|body|parsed|receipt|proof"
    r"|claim|attestation|vaa|bridgeMsg|bridgeMessage|envelope|inbound)"
)

_CANONICAL_PREFIX = (
    r"(?:route|request|req|expected|canonical|verified|commitment|params"
    r"|configured|settlement|transfer|order)"
)

_RECIPIENT_FIELD = (
    r"(?:Recipient|Receiver|To|ToAddress|Destination|DestinationAddress"
    r"|Target|TargetAddress|Beneficiary|Account|Address)"
)

_DOMAIN_FIELD = (
    r"(?:SourceChain|SrcChain|FromChain|OriginChain|DestinationChain"
    r"|DestChain|DstChain|ToChain|TargetChain|ChainID|ChainId"
    r"|SourceDomain|SrcDomain|OriginDomain|DestinationDomain"
    r"|DestDomain|DstDomain|TargetDomain|BridgeDomain|Domain"
    r"|SourceEID|DestinationEID|DstEID|Lane|LaneID|LaneId"
    r"|ChannelID|ChannelId|PortID|PortId|Emitter|EventEmitter"
    r"|EventNamespace|Namespace|RouteID|RouteId)"
)

_SUPPLIED_RECIPIENT_RE = re.compile(
    r"\b" + _SUPPLIED_PREFIX + r"\." + _RECIPIENT_FIELD + r"\b"
)

_CANONICAL_RECIPIENT_RE = re.compile(
    r"\b" + _CANONICAL_PREFIX + r"\." + _RECIPIENT_FIELD + r"\b"
    r"|\b(?:expectedRecipient|canonicalRecipient|routeRecipient"
    r"|verifiedRecipient|configuredRecipient|expectedReceiver"
    r"|canonicalReceiver|routeReceiver|configuredReceiver)\b",
    re.IGNORECASE,
)

_DOMAIN_RE = re.compile(
    r"\b(?:" + _SUPPLIED_PREFIX + r"|" + _CANONICAL_PREFIX + r"|k|s)\."
    + _DOMAIN_FIELD
    + r"\b"
    r"|\b(?:sourceChain|destinationChain|srcChain|dstChain"
    r"|sourceDomain|destinationDomain|srcDomain|dstDomain"
    r"|bridgeDomain|expectedDomain|routeDomain|configuredDomain"
    r"|expectedChain|routeChain|configuredChain|localDomain"
    r"|localChain|eventNamespace|expectedNamespace|laneID|channelID)\b",
    re.IGNORECASE,
)

_EVENT_LOCAL_FIELD_RE = re.compile(
    r"\b(?:MessageHash|PayloadHash|ProofHash|ReceiptHash|EventID|EventId"
    r"|MessageID|MessageId|ReceiptID|ReceiptId|WithdrawalID"
    r"|WithdrawalId|Leaf|LeafHash|Root|RootHash|Nonce|Sequence|Amount)"
    r"\b",
    re.IGNORECASE,
)

_KEY_NAME_RE = re.compile(
    r"(key|Key|leaf|Leaf|hash|Hash|digest|Digest|id|ID|commitment|Commitment)"
)

_HASH_CALL_RE = re.compile(
    r"\b(?:sha256\.Sum256|crypto\.Keccak256Hash|Keccak256Hash"
    r"|Hash(?:Bridge)?(?:Message|Event|Receipt|Proof|Leaf)?"
    r"|Build(?:Bridge)?(?:Message|Event|Receipt|Proof)?(?:Key|Leaf|Digest)"
    r"|MessageLeaf|EventLeaf|ReceiptLeaf|ProofLeaf)\s*\(",
    re.IGNORECASE,
)

_BINDING_HELPER_RE = re.compile(
    r"(Validate|Ensure|Assert|Bind|Check|Require|Verify)"
    r"[A-Za-z_]*(Bridge|Message|Event|Receipt|Proof)?"
    r"[A-Za-z_]*(Recipient|Receiver|Domain|Chain|Route|Lane|EID)"
    r"[A-Za-z_]*(Binding|Match|Matches|Bound|Scope|Scoped)?\s*\(",
    re.IGNORECASE,
)

_DOMAIN_KEY_HELPER_RE = re.compile(
    r"(Build|Hash|Bind|Scoped)[A-Za-z_]*(Bridge|Message|Event|Receipt|Proof)"
    r"[A-Za-z_]*(Domain|Chain|Route|Lane|Recipient)[A-Za-z_]*"
    r"(Key|Leaf|Digest|Hash)?\s*\(",
    re.IGNORECASE,
)

_PROCESSED_KEY_RE = re.compile(
    r"(?:processed(?:Messages|Events|Receipts|Proofs)?\s*\["
    r"|\.Seen\s*\(|\.HasProcessed\s*\(|\.AlreadyProcessed\s*\("
    r"|\.Mark\s*\(|\.MarkProcessed\s*\(|\.SetProcessed\s*\()"
    r"\s*(?P<expr>[^,\]\)\n]+)",
    re.IGNORECASE,
)

_COMPARISON_RE = re.compile(r"(?:==|!=|\.Equal\s*\(|\.Equals\s*\(|bytes\.Equal\s*\()")
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank, src)
    return re.sub(r"/\*.*?\*/", _blank, src, flags=re.S)


def _strip_comments_and_strings(src: str) -> str:
    return _STRING_RE.sub(_blank, _strip_comments(src))


def _term_pattern(term: str) -> str:
    return r"(?<![\w.])" + re.escape(term) + r"(?![\w.])"


def _mentions_any(text: str, terms: set[str]) -> bool:
    return any(re.search(_term_pattern(term), text) for term in terms)


def _extract_call(text: str, start: int) -> str:
    open_idx = text.find("(", start)
    if open_idx < 0:
        return text[start : start + 240]
    depth = 0
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start : idx + 1]
    return text[start : start + 240]


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


def _is_supplied_recipient(expr: str, aliases: set[str]) -> bool:
    return bool(_SUPPLIED_RECIPIENT_RE.search(expr)) or _mentions_any(expr, aliases)


def _is_canonical_recipient(expr: str, aliases: set[str]) -> bool:
    return bool(_CANONICAL_RECIPIENT_RE.search(expr)) or _mentions_any(expr, aliases)


def _is_domain_expr(expr: str, aliases: set[str]) -> bool:
    return bool(_DOMAIN_RE.search(expr)) or _mentions_any(expr, aliases)


def _is_event_local_expr(expr: str, aliases: set[str]) -> bool:
    return bool(_EVENT_LOCAL_FIELD_RE.search(expr)) or _mentions_any(expr, aliases)


def _is_domain_bound_expr(expr: str, aliases: set[str]) -> bool:
    return bool(_DOMAIN_KEY_HELPER_RE.search(expr)) or _is_domain_expr(expr, aliases)


def _collect_aliases(body_text: str) -> tuple[set[str], set[str], set[str], set[str], set[str]]:
    supplied: set[str] = set()
    canonical: set[str] = set()
    domains: set[str] = set()
    weak_keys: set[str] = set()
    bound_keys: set[str] = set()

    for line in body_text.splitlines():
        assign = _ASSIGN_RE.search(line)
        if not assign:
            continue
        lhs = assign.group(1)
        rhs = assign.group(2)
        key_like = bool(_KEY_NAME_RE.search(lhs) or _HASH_CALL_RE.search(rhs))

        if _is_supplied_recipient(rhs, supplied):
            supplied.add(lhs)
        elif _is_canonical_recipient(rhs, canonical):
            canonical.add(lhs)
        elif lhs in supplied or lhs in canonical:
            supplied.discard(lhs)
            canonical.discard(lhs)

        if _is_domain_expr(rhs, domains):
            domains.add(lhs)
        elif lhs in domains:
            domains.discard(lhs)

        if key_like and _is_domain_bound_expr(rhs, domains):
            bound_keys.add(lhs)
            weak_keys.discard(lhs)
            continue

        if key_like and _is_event_local_expr(rhs, weak_keys):
            weak_keys.add(lhs)
            bound_keys.discard(lhs)

    return supplied, canonical, domains, weak_keys, bound_keys


def _all_terms(body_text: str, direct_re: re.Pattern[str], aliases: set[str]) -> set[str]:
    terms = set(aliases)
    terms.update(match.group(0) for match in direct_re.finditer(body_text))
    return terms


def _has_pairwise_comparison(body_text: str, left_terms: set[str], right_terms: set[str]) -> bool:
    if not left_terms or not right_terms:
        return False
    for line in body_text.splitlines():
        if not _COMPARISON_RE.search(line):
            continue
        if _mentions_any(line, left_terms) and _mentions_any(line, right_terms):
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
    if _has_pairwise_comparison(body_text, supplied_terms, canonical_terms):
        return True
    for line in body_text.splitlines():
        if _DOMAIN_RE.search(line) and _COMPARISON_RE.search(line):
            return True
    return False


def _weak_key_expr(expr: str, weak_keys: set[str], bound_keys: set[str]) -> bool:
    expr = expr.strip()
    if _mentions_any(expr, bound_keys) or _DOMAIN_KEY_HELPER_RE.search(expr):
        return False
    if _mentions_any(expr, weak_keys) or _EVENT_LOCAL_FIELD_RE.search(expr):
        return True
    return False


def _weak_proof_site(body_text: str, weak_keys: set[str], bound_keys: set[str]) -> str | None:
    for match in _VERIFY_CALL_PREFIX_RE.finditer(body_text):
        call_text = _extract_call(body_text, match.start())
        args = " ".join(_split_call_args(call_text))
        if _weak_key_expr(args, weak_keys, bound_keys):
            return call_text.strip()
    return None


def _weak_processed_site(body_text: str, weak_keys: set[str], bound_keys: set[str]) -> str | None:
    for match in _PROCESSED_KEY_RE.finditer(body_text):
        expr = match.group("expr")
        if _weak_key_expr(expr, weak_keys, bound_keys):
            return match.group(0).strip()
    return None


def _supplied_sink_site(body_text: str, supplied_aliases: set[str]) -> str | None:
    for match in _SINK_CALL_PREFIX_RE.finditer(body_text):
        name = match.group("name").lower()
        call_text = _extract_call(body_text, match.start())
        args = _split_call_args(call_text)
        indexes = _RECIPIENT_ARG_INDEXES.get(name, tuple(range(len(args))))
        for index in indexes:
            if index < len(args) and _is_supplied_recipient(args[index], supplied_aliases):
                return call_text.strip()
    return None


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
        fn_text_clean = _strip_comments_and_strings(fn_text)
        body_text = _strip_comments_and_strings(engine.text(body))

        if not (_HANDLER_NAME_RE.search(name) or _BRIDGE_CONTEXT_RE.search(fn_text_clean)):
            continue
        if not _VERIFY_CALL_PREFIX_RE.search(body_text):
            continue

        supplied, canonical, domains, weak_keys, bound_keys = _collect_aliases(body_text)
        supplied_terms = _all_terms(body_text, _SUPPLIED_RECIPIENT_RE, supplied)
        canonical_terms = _all_terms(body_text, _CANONICAL_RECIPIENT_RE, canonical)
        domain_terms = _all_terms(body_text, _DOMAIN_RE, domains)

        if not supplied_terms:
            continue
        if not (canonical_terms or domain_terms):
            continue

        sink_site = _supplied_sink_site(body_text, supplied)
        if not sink_site:
            continue
        if _has_binding_guard(body_text, supplied_terms, canonical_terms, domain_terms):
            continue

        proof_site = _weak_proof_site(body_text, weak_keys, bound_keys)
        processed_site = _weak_processed_site(body_text, weak_keys, bound_keys)
        if not proof_site and not processed_site:
            continue

        evidence = proof_site or processed_site or sink_site
        hits.append(
            {
                "severity": "high",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` verifies a bridge proof or message near "
                    f"`{evidence}` and forwards value to a supplied recipient "
                    f"without binding recipient, chain, route, or domain "
                    f"context before the sink call. (class: "
                    f"bridge-proof-domain-bypass)"
                ),
            }
        )

    return hits
