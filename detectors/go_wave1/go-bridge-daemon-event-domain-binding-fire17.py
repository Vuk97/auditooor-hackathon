"""
go-bridge-daemon-event-domain-binding-fire17.py

Fire17 Go lift for bridge proof and event domain binding gaps.

Detects bridge daemons, relayers, and receipt consumers that accept a proof,
event, receipt, message, or settlement and then derive the replay key or proof
leaf from event-local data only. The vulnerable shape binds a leaf, message, or
event ID but omits source chain, destination chain, bridge domain, emitter, or
event namespace before forwarding value-bearing state.

This is recall-oriented detector evidence only. A hit is not a filing verdict.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-bridge-daemon-event-domain-binding-fire17"

_HANDLER_NAME_RE = re.compile(
    r"(Bridge|Daemon|Relayer|Relay|Event|Proof|Receipt|Message|Withdrawal"
    r"|Withdraw|Consume|Process|Finalize|Settle|Settlement|Claim|Forward)",
    re.IGNORECASE,
)

_BRIDGE_CONTEXT_RE = re.compile(
    r"(bridge|daemon|relayer|relay|event|receipt|proof|merkle|message"
    r"|settlement|withdrawal|sourceChain|destinationChain|bridgeDomain"
    r"|eventNamespace|emitter|eventID|txHash|logIndex|lane)",
    re.IGNORECASE,
)

_PROOF_OR_EVENT_RE = re.compile(
    r"(Verify(?:Proof|Event|Receipt|Message)?\s*\(|Validate(?:Proof|Event|Receipt|Message)?\s*\("
    r"|proof|Proof|merkle|Merkle|receipt|Receipt|event|Event|evt|log|Log)",
)

_VALUE_FORWARD_RE = re.compile(
    r"\b(?:Release|ReleaseTo|Forward|ForwardValue|ForwardMessage|Credit"
    r"|CreditAccount|Mint|MintTo|BridgeMint|Settle|SettleTo"
    r"|SettleReceipt|SettleWithdrawal|CompleteWithdrawal|FinalizeWithdrawal"
    r"|SendCoins|SendCoinsFromModuleToAccount|Transfer|TransferTo"
    r"|Payout|PayoutTo|Dispatch|DispatchMessage|Accept|AcceptReceipt)"
    r"\s*\(",
    re.IGNORECASE,
)

_CONSUME_OR_REPLAY_RE = re.compile(
    r"(processed|Processed|Seen\s*\(|HasProcessed\s*\(|AlreadyProcessed\s*\("
    r"|Mark\s*\(|MarkProcessed\s*\(|SetProcessed\s*\(|Replay|replay)",
)

_ASSIGN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?::=|=)\s*([^;\n]+)")

_KEY_NAME_RE = re.compile(
    r"(key|Key|digest|Digest|hash|Hash|leaf|Leaf|id|ID|eventID|eventId)",
)

_HASH_CALL_RE = re.compile(
    r"\b(?:sha256\.Sum256|crypto\.Keccak256Hash|Keccak256Hash|HashEvent"
    r"|HashMessage|HashReceipt|HashWithdrawal|HashLeaf"
    r"|Build(?:Event|Message|Receipt|Withdrawal)?(?:Key|Digest|Leaf)"
    r"|Digest(?:Event|Message|Receipt|Withdrawal)|EventLeaf"
    r"|ReceiptLeaf|MessageLeaf)\s*\(",
    re.IGNORECASE,
)

_PROCESSED_KEY_RE = re.compile(
    r"(?:processed(?:Events|Messages|Receipts|Withdrawals)?\s*\["
    r"|\.Seen\s*\(|\.HasProcessed\s*\(|\.AlreadyProcessed\s*\("
    r"|\.Mark\s*\(|\.MarkProcessed\s*\(|\.SetProcessed\s*\()"
    r"\s*(?P<expr>[^,\]\)\n]+)",
    re.IGNORECASE,
)

_VERIFY_CALL_RE = re.compile(
    r"\b(?:Verify(?:Bridge)?(?:Proof|Event|Receipt|Message)?"
    r"|Validate(?:Bridge)?(?:Proof|Event|Receipt|Message)?)\s*\("
    r"(?P<args>[^\n]+)\)",
    re.IGNORECASE,
)

_EVENT_LOCAL_FIELD_RE = re.compile(
    r"\b(?:EventID|EventId|MessageID|MessageId|ReceiptID|ReceiptId"
    r"|WithdrawalID|WithdrawalId|PayloadHash|MessageHash|ReceiptHash"
    r"|ProofHash|Leaf|LeafHash|Root|RootHash|EventRoot|Amount|Nonce|ID)"
    r"\b",
    re.IGNORECASE,
)

_DOMAIN_FIELD_RE = re.compile(
    r"\b(?:SourceChain|SrcChain|FromChain|OriginChain|DestinationChain"
    r"|DstChain|ToChain|TargetChain|ChainID|ChainId|SourceDomain"
    r"|SrcDomain|OriginDomain|BridgeDomain|DestinationDomain|DstDomain"
    r"|TargetDomain|Emitter|EventEmitter|EmitterAddress|EventNamespace"
    r"|Namespace|ContractAddress|BridgeAddress|TxHash|TransactionHash"
    r"|LogIndex|LogIdx|Lane|LaneID|LaneId|ChannelID|ChannelId|PortID"
    r"|PortId|Sequence|RouteID|RouteId)\b",
    re.IGNORECASE,
)

_NAMED_DOMAIN_BINDING_RE = re.compile(
    r"(DomainBound|DomainBinding|Bind(?:Event|Proof|Message|Receipt|Withdrawal)?Domain"
    r"|Build(?:Bridge)?(?:Event|Proof|Message|Receipt|Withdrawal)?Domain"
    r"|Build(?:Bridge)?(?:Event|Proof|Message|Receipt|Withdrawal)?DomainKey"
    r"|Scoped(?:Event|Proof|Message|Receipt|Withdrawal)?Key"
    r"|EventDomainKey|ProofDomainKey|MessageDomainKey|ReceiptDomainKey"
    r"|WithdrawalDomainKey|Validate(?:Event|Proof|Message|Receipt|Withdrawal)?Domain"
    r"|ValidateEventDomainBinding|Ensure(?:Event|Proof|Receipt|Message)?Domain"
    r"|Check(?:Event|Proof|Receipt|Message)?Domain)",
    re.IGNORECASE,
)

_DOMAIN_GUARD_RE = re.compile(
    r"(Validate|Ensure|Assert|Bind|Check|Require|Verify)"
    r"[A-Za-z_]*(Domain|Chain|Emitter|Namespace|Lane|Route)"
    r"[A-Za-z_]*(Binding|Match|Matches|Bound|Scope|Scoped)?\s*\(",
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


def _has_domain_binding(expr: str, domain_vars: set[str]) -> bool:
    return (
        bool(_NAMED_DOMAIN_BINDING_RE.search(expr))
        or bool(_DOMAIN_FIELD_RE.search(expr))
        or _mentions_any(expr, domain_vars)
    )


def _has_event_local(expr: str, weak_vars: set[str]) -> bool:
    return bool(_EVENT_LOCAL_FIELD_RE.search(expr)) or _mentions_any(expr, weak_vars)


def _has_domain_guard(body_text: str) -> bool:
    if _DOMAIN_GUARD_RE.search(body_text):
        return True
    for line in body_text.splitlines():
        if _DOMAIN_FIELD_RE.search(line) and _COMPARISON_RE.search(line):
            return True
    return False


def _collect_key_vars(body_text: str) -> tuple[set[str], set[str], list[str]]:
    weak_vars: set[str] = set()
    domain_vars: set[str] = set()
    weak_sites: list[str] = []

    for line in body_text.splitlines():
        assign = _ASSIGN_RE.search(line)
        if not assign:
            continue
        lhs = assign.group(1)
        rhs = assign.group(2)
        key_like = bool(_KEY_NAME_RE.search(lhs) or _HASH_CALL_RE.search(rhs))

        if _has_domain_binding(rhs, domain_vars):
            domain_vars.add(lhs)
            weak_vars.discard(lhs)
            continue

        if key_like and _has_event_local(rhs, weak_vars):
            weak_vars.add(lhs)
            weak_sites.append(line.strip())
            domain_vars.discard(lhs)

    return weak_vars, domain_vars, weak_sites


def _expr_is_weak(expr: str, weak_vars: set[str], domain_vars: set[str]) -> bool:
    expr = expr.strip()
    if _has_domain_binding(expr, domain_vars):
        return False
    return _has_event_local(expr, weak_vars)


def _weak_processed_site(
    body_text: str, weak_vars: set[str], domain_vars: set[str]
) -> str | None:
    for match in _PROCESSED_KEY_RE.finditer(body_text):
        expr = match.group("expr")
        if _expr_is_weak(expr, weak_vars, domain_vars):
            return match.group(0).strip()
    return None


def _weak_proof_site(
    body_text: str, weak_vars: set[str], domain_vars: set[str]
) -> str | None:
    for match in _VERIFY_CALL_RE.finditer(body_text):
        args = match.group("args")
        if _expr_is_weak(args, weak_vars, domain_vars):
            return match.group(0).strip()
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
        if not _PROOF_OR_EVENT_RE.search(fn_text_clean):
            continue
        if not (_VALUE_FORWARD_RE.search(fn_text_clean) or _CONSUME_OR_REPLAY_RE.search(fn_text_clean)):
            continue
        if _has_domain_guard(body_text):
            continue

        weak_vars, domain_vars, weak_sites = _collect_key_vars(body_text)
        processed_site = _weak_processed_site(body_text, weak_vars, domain_vars)
        proof_site = _weak_proof_site(body_text, weak_vars, domain_vars)
        if not processed_site and not proof_site:
            continue

        site = processed_site or proof_site or (weak_sites[0] if weak_sites else "event-local key")
        hits.append(
            {
                "severity": "high",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` accepts a bridge event, receipt, or proof with "
                    f"a non-domain-bound key near `{site}`. Bridge proof and "
                    f"daemon settlement keys should bind source chain, "
                    f"destination chain, bridge domain, emitter, event "
                    f"namespace, or lane context before forwarding "
                    f"value-bearing state. (class: bridge-proof-domain-bypass)"
                ),
            }
        )

    return hits
