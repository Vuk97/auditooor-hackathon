"""
bridge-outbound-zero-fee-floor-fire29.

Solidity recall-lift detector for outbound bridge entrypoints that accept a
caller-supplied execution, destination, remote, relayer, or message fee, then
emit, queue, or relay the outbound message without a source-chain minimum fee
floor. It also catches paths where the message is accepted before any fee
validation or collection.

Lineage:
- reference/patterns.dsl/bridge-outbound-no-fee-floor-zero-message-spam.yaml
- reference/patterns.dsl/bridge-relayer-reward-paid-on-failed-dispatch.yaml
- reference/patterns.dsl/two-hop-bridge-transfer-restriction-bypass.yaml

Hits are candidate evidence only. They prove source-shape recall, not filing
readiness. A report still needs a real protocol path, non-DoS impact framing,
and a negative control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-outbound-zero-fee-floor-fire29"
DETECTOR_SEVERITY_DEFAULT = "Medium"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


@dataclass
class FunctionSlice:
    name: str
    header: str
    body: str
    body_line: int


_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b")

_BRIDGE_CONTEXT_RE = re.compile(
    r"\b(?:bridge|gateway|portal|crosschain|crossChain|cross[-_ ]?chain|"
    r"outbound|remote|destination|dest|dst|route|lane|channel|endpoint|"
    r"relayer|relay|message|payload|packet|xcm|sendMessage|sendToken|"
    r"queueMessage|queuedMessage|dispatch)\b",
    re.IGNORECASE,
)
_OUTBOUND_NAME_RE = re.compile(
    r"\b(?:send|sendMessage|sendToken|bridge|bridgeOut|outbound|"
    r"queue|queueMessage|dispatch|relay|route|crossChain)\w*\b",
    re.IGNORECASE,
)
_FEE_WORD_RE = re.compile(
    r"\b(?:executionFee|destinationFee|destFee|remoteFee|targetChainFee|"
    r"relayerFee|messageFee|bridgeFee|dispatchFee|nativeFee|lzFee|"
    r"feeQuote|quotedFee|totalFee|fee)\b",
    re.IGNORECASE,
)
_MSG_VALUE_FEE_RE = re.compile(
    r"\b(?:require|if)\s*\([^;{}]*msg\.value[^;{}]*(?:[Ff]ee|totalFee|"
    r"quotedFee|feeQuote|nativeFee|lzFee)[^;{}]*\)|"
    r"\bmsg\.value\s*(?:==|!=|>=|>|<=|<)\s*[^;{}]*(?:[Ff]ee|totalFee|"
    r"quotedFee|feeQuote|nativeFee|lzFee)|"
    r"\b(?:[Ff]ee|totalFee|quotedFee|feeQuote|nativeFee|lzFee)[^;{}]*"
    r"\s*(?:==|!=|<=|<|>=|>)\s*msg\.value",
    re.IGNORECASE | re.DOTALL,
)
_FEE_FORWARD_RE = re.compile(
    r"\b(?:Message|Packet|Outbound|Dispatch|Route|Bridge)[A-Za-z0-9_]*\s*\("
    r"[^;{}]*(?:executionFee|destinationFee|destFee|remoteFee|targetChainFee|"
    r"relayerFee|messageFee|bridgeFee|dispatchFee|nativeFee|lzFee|fee)\b|"
    r"\b(?:abi\.encode|abi\.encodePacked)\s*\([^;{}]*(?:executionFee|"
    r"destinationFee|destFee|remoteFee|targetChainFee|relayerFee|messageFee|"
    r"bridgeFee|dispatchFee|nativeFee|lzFee)\b",
    re.IGNORECASE | re.DOTALL,
)
_ACCEPTANCE_RE = re.compile(
    r"\b(?:outbound|queued|pending|messages?|packets?|bridgeMessages?|"
    r"outboundMessages?|outboundQueue|messageQueue|packetQueue)\s*"
    r"(?:\[[^\]]+\]\s*){0,4}(?:=|\.push\s*\(|\.add\s*\(|\.set\s*\()|"
    r"\b(?:outboundNonce|messageNonce|nextNonce|nonce)\s*(?:\+\+|\+=\s*1)|"
    r"\bemit\s+[A-Za-z_][A-Za-z0-9_]*(?:Outbound|Bridge|Message|Packet|"
    r"Queued|Relayed|Sent|Dispatched)[A-Za-z0-9_]*\s*\(|"
    r"\b(?:_sendMessage|sendMessage|_dispatch|dispatch|_relay|relay)"
    r"[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_FEE_COLLECTION_RE = re.compile(
    r"\b(?:safeTransferFrom|transferFrom)\s*\([^;{}]*msg\.sender[^;{}]*"
    r"(?:[Ff]ee|totalFee|nativeFee|lzFee)|"
    r"\b(?:_collectFee|collectFee|payFee|chargeFee|_chargeFee)\s*\("
    r"[^;{}]*(?:[Ff]ee|totalFee|nativeFee|lzFee)|"
    r"\bpayable\s*\([^;{}]+\)\s*\.\s*call\s*\{\s*value\s*:\s*"
    r"[^;{}]*(?:[Ff]ee|totalFee|nativeFee|lzFee)",
    re.IGNORECASE | re.DOTALL,
)
_FEE_FLOOR_RE = re.compile(
    r"\brequire\s*\([^;{}]*(?:executionFee|destinationFee|destFee|remoteFee|"
    r"targetChainFee|relayerFee|messageFee|bridgeFee|dispatchFee|nativeFee|"
    r"lzFee|fee)\b[^;{}]*(?:>=|>)\s*(?:MIN[A-Z0-9_]*|min[A-Za-z0-9_]*|"
    r"minimum[A-Za-z0-9_]*|floor[A-Za-z0-9_]*|quote[A-Za-z0-9_]*\s*\(|"
    r"estimate[A-Za-z0-9_]*\s*\(|feeOracle|quotedFee|feeQuote)|"
    r"\bif\s*\([^;{}]*(?:executionFee|destinationFee|destFee|remoteFee|"
    r"targetChainFee|relayerFee|messageFee|bridgeFee|dispatchFee|nativeFee|"
    r"lzFee|fee)\b[^;{}]*(?:<|<=|==)\s*(?:0|MIN[A-Z0-9_]*|"
    r"min[A-Za-z0-9_]*|minimum[A-Za-z0-9_]*|floor[A-Za-z0-9_]*|"
    r"quote[A-Za-z0-9_]*\s*\(|estimate[A-Za-z0-9_]*\s*\(|feeOracle|"
    r"quotedFee|feeQuote)\s*\)[^;{}]*(?:revert|return)|"
    r"\b(?:FeeTooLow|InsufficientFee|InvalidFee|ZeroFee|MinFee|"
    r"MinimumFee|FeeBelowFloor)\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_EMPTY_MESSAGE_GUARD_RE = re.compile(
    r"\brequire\s*\([^;{}]*(?:payload|message|xcm|callData|data|assets|"
    r"tokens|amount)\s*(?:\.length\s*)?>\s*0|"
    r"\bif\s*\([^;{}]*(?:payload|message|xcm|callData|data|assets|tokens|"
    r"amount)\s*(?:\.length\s*)?(?:==|<=)\s*0\s*\)[^;{}]*(?:revert|return)|"
    r"\b(?:EmptyMessage|InvalidEmpty|NoPayload|NoAssets|ZeroAmount)\s*\(",
    re.IGNORECASE | re.DOTALL,
)


def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    if open_brace < 0 or open_brace >= len(source) or source[open_brace] != "{":
        return None, open_brace
    depth = 1
    i = open_brace + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        i += 1
    if depth != 0:
        return None, open_brace
    return source[open_brace + 1:i - 1], i


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        i = match.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            char = source[i]
            if char == "(":
                depth_paren += 1
            elif char == ")":
                depth_paren -= 1
            i += 1

        body_start = -1
        j = i
        while j < len(source):
            if source[j] == ";":
                break
            if source[j] == "{":
                body_start = j
                break
            j += 1
        if body_start < 0:
            pos = max(j, i)
            continue

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _context(fn: FunctionSlice) -> str:
    return f"{fn.name}\n{fn.header}\n{fn.body}"


def _line_for(fn: FunctionSlice, pos: int) -> int:
    return fn.body_line + fn.body.count("\n", 0, max(0, pos))


def _first_match(pattern: re.Pattern[str], text: str) -> re.Match[str] | None:
    return pattern.search(text)


def _is_public_mutating(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _has_outbound_fee_surface(fn: FunctionSlice) -> bool:
    text = _context(fn)
    return (
        bool(_OUTBOUND_NAME_RE.search(fn.name) or _BRIDGE_CONTEXT_RE.search(text))
        and bool(_FEE_WORD_RE.search(text))
        and bool(_MSG_VALUE_FEE_RE.search(fn.body) or _FEE_FORWARD_RE.search(fn.body))
    )


def _acceptance_before_fee_handling(fn: FunctionSlice, accept: re.Match[str]) -> bool:
    fee_guard = _first_match(_MSG_VALUE_FEE_RE, fn.body)
    fee_collect = _first_match(_FEE_COLLECTION_RE, fn.body)
    first_fee_pos = min(
        [m.start() for m in (fee_guard, fee_collect) if m is not None],
        default=-1,
    )
    return first_fee_pos >= 0 and accept.start() < first_fee_pos


def _zero_fee_floor_result(fn: FunctionSlice) -> tuple[int, str] | None:
    if not _is_public_mutating(fn):
        return None
    if not _has_outbound_fee_surface(fn):
        return None

    accept = _first_match(_ACCEPTANCE_RE, fn.body)
    if accept is None:
        return None

    floor = _first_match(_FEE_FLOOR_RE, fn.body)
    if floor is not None and floor.start() < accept.start():
        return None

    if _acceptance_before_fee_handling(fn, accept):
        return (
            accept.start(),
            "queues, emits, or relays the outbound message before fee validation or collection",
        )

    if floor is None:
        if _EMPTY_MESSAGE_GUARD_RE.search(fn.body):
            reason = "has an empty-message guard but no minimum outbound fee floor"
        else:
            reason = "has no minimum outbound fee floor and no empty-message rejection"
        fee_match = _first_match(_MSG_VALUE_FEE_RE, fn.body) or _first_match(_FEE_FORWARD_RE, fn.body)
        return ((fee_match.start() if fee_match is not None else accept.start()), reason)

    return (
        accept.start(),
        "accepts the outbound message before the minimum outbound fee floor is enforced",
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    if not _BRIDGE_CONTEXT_RE.search(code):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(code):
        result = _zero_fee_floor_result(fn)
        if result is None:
            continue
        pos, reason = result
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn, pos),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` {reason}. Outbound bridge messages need a "
                    "source-chain fee floor before nonce consumption, queue "
                    "writes, relay, or outbound events. Candidate evidence only."
                ),
            )
        )
    return findings


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "scan",
]
