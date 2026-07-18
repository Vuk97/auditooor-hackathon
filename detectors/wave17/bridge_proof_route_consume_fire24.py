"""
bridge-proof-route-consume-fire24.

Solidity recall-lift detector for bridge proof consumers where mutable route
state, fee-floor bypass, or non-reverting dispatch failure is composed with a
processed or consumed key that is not tied to the message id plus chain domain.

This is candidate evidence only. A hit must show a bridge proof consumer that
reads route state, dispatches the message, writes a consumed or processed flag,
and has a weak consume key while at least one Fire23 bridge route trigger is
present.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-proof-route-consume-fire24"
DETECTOR_SEVERITY_DEFAULT = "High"


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
_BRIDGE_CONTEXT_RE = re.compile(
    r"\b(?:bridge|gateway|crosschain|crossChain|cross[-_ ]?chain|relay|"
    r"relayer|route|router|message|dispatch|proof|root|commitment|"
    r"packet|payload|lane|endpoint|domain|chain)\b",
    re.IGNORECASE,
)
_PROOF_CONTEXT_RE = re.compile(
    r"\b(?:proof|proofs|root|stateRoot|messageRoot|receiptRoot|leaf|"
    r"leafHash|MerkleProof|verifyProof|verifyMessage|verifyRoot|"
    r"verifyCommitment|messageHash|proofDigest)\b",
    re.IGNORECASE,
)
_ROUTE_READ_RE = re.compile(
    r"\b(?:routes?|routeBy\w*|adapters?|adapterBy\w*|messengers?|"
    r"messengerBy\w*|verifiers?|verifierBy\w*|dispatchers?|"
    r"dispatcherBy\w*)\s*(?:\[[^\]]+\]\s*){1,3}"
    r"|\broute\s*\.\s*(?:adapter|messenger|verifier|dispatcher|router)"
    r"|\b(?:router|dispatcher|verifier)\s*=\s*route\.",
    re.IGNORECASE | re.DOTALL,
)
_ROUTE_WRITE_RE = re.compile(
    r"\b(?:routes?|routeBy\w*|adapters?|adapterBy\w*|messengers?|"
    r"messengerBy\w*|verifiers?|verifierBy\w*|dispatchers?|"
    r"dispatcherBy\w*)\s*(?:\[[^\]]+\]\s*){1,3}="
    r"|\b(?:routes?|adapters?|messengers?|verifiers?|dispatchers?)"
    r"\s*\[[^\]]+\]\s*\.",
    re.IGNORECASE | re.DOTALL,
)
_ROUTE_SETTER_NAME_RE = re.compile(
    r"^(?:set|configure|register|update|initialize|migrate)"
    r"[A-Za-z0-9_]*(?:Route|Router|Adapter|Messenger|Verifier|Peer|Remote|"
    r"Gateway|Dispatcher|Lane|Endpoint)$",
    re.IGNORECASE,
)
_AUTH_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|"
    r"onlyRole|onlyOperator|onlyManager|onlyConfigurator|onlyTimelock|"
    r"requires?Auth|authorized|isAuthorized|hasRole|_checkOwner|"
    r"_authorize)\b"
    r"|require\s*\([^;{}]*msg\.sender\s*==\s*"
    r"(?:owner|admin|governance|governor|factory|operator|manager|"
    r"configurator|timelock|controller)",
    re.IGNORECASE | re.DOTALL,
)
_DISPATCH_RE = re.compile(
    r"\b(?:dispatch|deliver|execute|relay|sendMessage|forwardMessage)"
    r"\s*\("
    r"|\.call\s*(?:\{|\()"
    r"|functionCall\s*\("
    r"|IDispatcher\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_CONSUME_RE = re.compile(
    r"\b(?P<flag>(?:consumed|processed|used|delivered|finalized|executed|"
    r"relayed|dispatched|seen|spent|messageConsumed|receiptConsumed)"
    r"[A-Za-z0-9_]*)\s*\[\s*(?P<key>[^\]]+)\]\s*=\s*true\b|"
    r"\b(?P<setflag>(?:consumed|processed|used|delivered|finalized|executed|"
    r"relayed|dispatched|seen|spent)[A-Za-z0-9_]*)\s*\.\s*(?:set|add)\s*\("
    r"\s*(?P<setkey>[^),]+)",
    re.IGNORECASE | re.DOTALL,
)
_HASH_ASSIGN_RE = re.compile(
    r"\b(?:bytes32\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*"
    r"(?:Key|Id|ID|Hash|Digest|Nonce|Leaf|Receipt)?)\s*=\s*"
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,1000}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_FEE_CONTEXT_RE = re.compile(
    r"\b(?:executionFee|destinationFee|destFee|remoteFee|targetChainFee|"
    r"relayerFee|relayFee|messageFee)\b",
    re.IGNORECASE,
)
_MSG_VALUE_RE = re.compile(r"\bmsg\.value\b")
_FEE_FLOOR_RE = re.compile(
    r"\b(?:MIN_[A-Za-z0-9_]*FEE|MINIMUM_[A-Za-z0-9_]*FEE|min[A-Za-z0-9_]*Fee|"
    r"minimum[A-Za-z0-9_]*Fee|feeFloor|FeeTooLow|executionFee\s*>?=\s*MIN_|"
    r"destinationFee\s*>?=\s*MIN_|relayerFee\s*>?=\s*MIN_)\b",
    re.IGNORECASE,
)
_NONREVERTING_FAILURE_RE = re.compile(
    r"\bif\s*\(\s*!\s*(?:success|ok|delivered|dispatched|accepted)\s*\)"
    r"\s*\{[^{}]*(?:return\s*;|return\s+false\s*;|continue\s*;|"
    r"emit\s+[A-Za-z_][A-Za-z0-9_]*\s*\()"
    r"|\bcatch\s*(?:\([^)]*\))?\s*\{[^{}]*(?:return\s*;|"
    r"return\s+false\s*;|continue\s*;|success\s*=\s*false|ok\s*=\s*false)",
    re.IGNORECASE | re.DOTALL,
)
_ATOMIC_FAILURE_RE = re.compile(
    r"\b(?:require\s*\(\s*(?:success|ok|delivered|dispatched|accepted)\s*[,)]|"
    r"revert\s+[A-Za-z_][A-Za-z0-9_]*\s*\(|\brevert\b|DispatchFailed|"
    r"RouteFailed|MessageFailed)\b",
    re.IGNORECASE | re.DOTALL,
)
_MESSAGE_ID_RE = re.compile(r"\b(?:messageId|msgId|messageHash|packetId|nonce|root|leaf|proofDigest)\b", re.IGNORECASE)
_SOURCE_DOMAIN_RE = re.compile(r"\b(?:source|src|origin|remote|from)\w*(?:Chain|ChainId|Domain|DomainId|Eid)\b", re.IGNORECASE)
_DEST_DOMAIN_RE = re.compile(r"\b(?:destination|dest|dst|target|local|to)\w*(?:Chain|ChainId|Domain|DomainId|Eid)\b", re.IGNORECASE)
_ROUTE_DOMAIN_RE = re.compile(r"\b(?:route|routeId|routeKey|lane|channel|endpoint|dispatcher|router|verifier)\w*\b", re.IGNORECASE)
_LOCAL_DOMAIN_RE = re.compile(r"\b(?:BRIDGE_DOMAIN|DOMAIN|domain|chainId|chainid|block\.chainid|address\s*\(\s*this\s*\))\b", re.IGNORECASE)


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


def _line_for(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _assigned_expr_before(body: str, name: str, pos: int) -> str:
    found = ""
    for match in _HASH_ASSIGN_RE.finditer(body[:pos]):
        if match.group("name") == name:
            found = match.group("expr")
    return found


def _has_full_consume_domain(expr: str) -> bool:
    return (
        bool(_MESSAGE_ID_RE.search(expr))
        and bool(_SOURCE_DOMAIN_RE.search(expr))
        and bool(_DEST_DOMAIN_RE.search(expr))
        and bool(_ROUTE_DOMAIN_RE.search(expr))
        and bool(_LOCAL_DOMAIN_RE.search(expr))
    )


def _weak_consume_key(body: str, match: re.Match[str]) -> bool:
    key = (match.group("key") or match.group("setkey") or "").strip()
    if not key:
        return False
    key_expr = _assigned_expr_before(body, key, match.start())
    if not key_expr:
        key_expr = key

    if _has_full_consume_domain(key_expr):
        return False
    return bool(_MESSAGE_ID_RE.search(key_expr) or _PROOF_CONTEXT_RE.search(key_expr))


def _weak_route_setters(functions: list[FunctionSlice]) -> list[str]:
    setters: list[str] = []
    for fn in functions:
        if not _PUBLIC_HEADER_RE.search(fn.header):
            continue
        if not _ROUTE_SETTER_NAME_RE.search(fn.name):
            continue
        text = _context(fn)
        if not _ROUTE_WRITE_RE.search(text):
            continue
        if _AUTH_RE.search(text):
            continue
        setters.append(fn.name)
    return setters


def _has_fee_floor_bypass(fn: FunctionSlice) -> bool:
    text = _context(fn)
    return bool(_FEE_CONTEXT_RE.search(text) and _MSG_VALUE_RE.search(text) and not _FEE_FLOOR_RE.search(text))


def _has_nonreverting_failure(fn: FunctionSlice) -> bool:
    failure = _NONREVERTING_FAILURE_RE.search(fn.body)
    if failure is None:
        return False
    atomic = _ATOMIC_FAILURE_RE.search(fn.body[failure.start():])
    return atomic is None or atomic.start() > failure.end() - failure.start()


def _is_bridge_consumer(fn: FunctionSlice) -> bool:
    text = _context(fn)
    return (
        bool(_PUBLIC_HEADER_RE.search(fn.header))
        and bool(_BRIDGE_CONTEXT_RE.search(text))
        and bool(_PROOF_CONTEXT_RE.search(text))
        and bool(_ROUTE_READ_RE.search(text))
        and bool(_DISPATCH_RE.search(text))
    )


def _trigger_reasons(fn: FunctionSlice, setters: list[str]) -> list[str]:
    reasons: list[str] = []
    if setters and _ROUTE_READ_RE.search(_context(fn)):
        reasons.append("permissionless route mutation")
    if _has_fee_floor_bypass(fn):
        reasons.append("fee floor bypass")
    if _has_nonreverting_failure(fn):
        reasons.append("non-reverting dispatch failure")
    return reasons


def _finding(file_path: str, line: int, function: str, reasons: list[str]) -> Finding:
    reason_text = ", ".join(reasons)
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            f"{reason_text} feeds bridge proof route consumption with a weak "
            "processed key that is not tied to message id plus chain domain. "
            "Candidate evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    functions = _split_functions(code)
    setters = _weak_route_setters(functions)
    findings: list[Finding] = []
    for fn in functions:
        if not _is_bridge_consumer(fn):
            continue
        reasons = _trigger_reasons(fn, setters)
        if not reasons:
            continue
        for match in _CONSUME_RE.finditer(fn.body):
            if not _weak_consume_key(fn.body, match):
                continue
            findings.append(_finding(file_path, _line_for(fn, match), fn.name, reasons))
            break
    return findings
