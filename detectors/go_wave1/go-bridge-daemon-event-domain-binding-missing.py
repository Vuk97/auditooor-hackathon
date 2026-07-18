"""
go-bridge-daemon-event-domain-binding-missing.py

Detects Go bridge daemon, relayer, and event-consumer paths that validate or
consume a bridge event, proof, message, or withdrawal while deriving the
replay/processed key from a payload-local hash only. The detector is scoped to
domain-bypass shapes where the processed key or proof digest omits source chain,
destination chain, event emitter, tx hash, log index, recipient, or lane
binding.

This intentionally does not duplicate the existing recipient-sink detectors:
it only fires when a bridge/event path has proof or event validation plus a
processed/replay key derived from a non-domain-bound event field.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-bridge-daemon-event-domain-binding-missing"

_HANDLER_NAME_RE = re.compile(
    r"(Bridge|Daemon|Relayer|Relay|Event|Proof|Message|Withdrawal|Withdraw"
    r"|Consume|Process|Finalize|Settle|Claim)",
    re.IGNORECASE,
)

_BRIDGE_BODY_RE = re.compile(
    r"(bridge|daemon|relayer|relay|event|evt|proof|merkle|receipt|message"
    r"|withdrawal|sourceChain|destinationChain|emitter|txHash|logIndex|lane)",
    re.IGNORECASE,
)

_PROOF_OR_EVENT_RE = re.compile(
    r"(Verify(?:Proof|Event|Receipt|Message)?\s*\(|Validate(?:Proof|Event|Receipt|Message)?\s*\("
    r"|proof|Proof|merkle|Merkle|receipt|Receipt|event|Event|evt|log|Log)",
)

_CONSUME_OR_REPLAY_RE = re.compile(
    r"(processed|Processed|Seen\s*\(|HasProcessed\s*\(|AlreadyProcessed\s*\("
    r"|Mark\s*\(|MarkProcessed\s*\(|SetProcessed\s*\(|Replay|replay)",
)

_KEY_ASSIGN_RE = re.compile(
    r"\b(?P<lhs>[A-Za-z_]\w*(?:key|Key|digest|Digest|hash|Hash|leaf|Leaf|id|ID)[A-Za-z_0-9]*)"
    r"\s*(?::=|=)\s*(?P<rhs>[^;\n]+)"
)

_HASH_CALL_RE = re.compile(
    r"\b(?:sha256\.Sum256|crypto\.Keccak256Hash|Keccak256Hash|HashEvent"
    r"|HashMessage|HashWithdrawal|HashLeaf|Build(?:Event|Message|Withdrawal)?Digest"
    r"|Digest(?:Event|Message|Withdrawal))\s*\(",
    re.IGNORECASE,
)

_DIRECT_PROCESSED_KEY_RE = re.compile(
    r"(?:processed(?:Events|Messages|Withdrawals)?\s*\[|\.Seen\s*\("
    r"|\.HasProcessed\s*\(|\.AlreadyProcessed\s*\(|\.Mark\s*\("
    r"|\.MarkProcessed\s*\(|\.SetProcessed\s*\()\s*(?P<expr>[^,\]\)\n]+)",
    re.IGNORECASE,
)

_WEAK_EVENT_FIELD_RE = re.compile(
    r"\b(?:MessageHash|PayloadHash|ProofHash|Leaf|LeafHash|Root|RootHash"
    r"|Amount|Nonce|ID|EventID|WithdrawalID)\b",
    re.IGNORECASE,
)

_DOMAIN_FIELD_RE = re.compile(
    r"\b(?:SourceChain|SrcChain|FromChain|OriginChain|DestinationChain|DstChain"
    r"|ToChain|TargetChain|ChainID|ChainId|SourceDomain|SrcDomain"
    r"|DestinationDomain|DstDomain|Emitter|EventEmitter|EmitterAddress"
    r"|ContractAddress|BridgeAddress|TxHash|TransactionHash|LogIndex|LogIdx"
    r"|Recipient|Receiver|Beneficiary|Lane|LaneID|LaneId|ChannelID|ChannelId"
    r"|PortID|PortId|Sequence)\b",
    re.IGNORECASE,
)

_NAMED_DOMAIN_BINDING_RE = re.compile(
    r"(DomainBound|DomainBinding|Bind(?:Event|Proof|Message|Withdrawal)?Domain"
    r"|BuildDomain|Scoped(?:Event|Proof|Message|Withdrawal)?Key"
    r"|EventDomainKey|ProofDomainKey|MessageDomainKey|WithdrawalDomainKey"
    r"|Validate(?:Event|Proof|Message|Withdrawal)?Domain)",
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


def _is_weak_domain_expr(expr: str) -> bool:
    if _NAMED_DOMAIN_BINDING_RE.search(expr):
        return False
    if _DOMAIN_FIELD_RE.search(expr):
        return False
    return bool(_WEAK_EVENT_FIELD_RE.search(expr))


def _collect_weak_key_assignments(body_text: str) -> tuple[set[str], list[tuple[str, str]]]:
    weak_vars: set[str] = set()
    sites: list[tuple[str, str]] = []

    for line in body_text.splitlines():
        assign = _KEY_ASSIGN_RE.search(line)
        if not assign:
            continue
        rhs = assign.group("rhs")
        if not _HASH_CALL_RE.search(rhs):
            continue
        if not _is_weak_domain_expr(rhs):
            continue
        lhs = assign.group("lhs")
        weak_vars.add(lhs)
        sites.append((lhs, line.strip()))

    return weak_vars, sites


def _expr_is_weak_processed_key(expr: str, weak_vars: set[str]) -> bool:
    expr = expr.strip()
    if expr in weak_vars:
        return True
    if _NAMED_DOMAIN_BINDING_RE.search(expr):
        return False
    if _DOMAIN_FIELD_RE.search(expr):
        return False
    return bool(_WEAK_EVENT_FIELD_RE.search(expr))


def _has_weak_processed_use(body_text: str, weak_vars: set[str]) -> bool:
    for match in _DIRECT_PROCESSED_KEY_RE.finditer(body_text):
        if _expr_is_weak_processed_key(match.group("expr"), weak_vars):
            return True
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
        fn_text_clean = _strip_comments_and_strings(fn_text)
        body_text = _strip_comments_and_strings(engine.text(body))

        if not (_HANDLER_NAME_RE.search(name) or _BRIDGE_BODY_RE.search(fn_text_clean)):
            continue
        if not _PROOF_OR_EVENT_RE.search(fn_text_clean):
            continue
        if not _CONSUME_OR_REPLAY_RE.search(fn_text_clean):
            continue

        weak_vars, weak_sites = _collect_weak_key_assignments(body_text)
        if not weak_sites and not _has_weak_processed_use(body_text, weak_vars):
            continue
        if weak_vars and not _has_weak_processed_use(body_text, weak_vars):
            continue

        site = weak_sites[0][1] if weak_sites else "processed key uses payload-local event field"
        hits.append(
            {
                "severity": "high",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` validates or consumes a bridge event/proof with "
                    f"a non-domain-bound processed key near `{site}`. Bridge "
                    f"daemon replay keys and proof digests should bind source "
                    f"chain, destination chain, emitter, tx hash, log index, "
                    f"recipient, or lane context. "
                    f"(class: bridge-proof-domain-bypass)"
                ),
            }
        )

    return hits
