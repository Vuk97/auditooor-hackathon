"""
bridge-permissionless-route-setter-fire25.

Solidity recall-lift detector for bridge route, receiver, endpoint, adapter,
or channel setters that are public without owner, admin, factory, protocol, or
role binding while a later proof or dispatch entrypoint reads that mutable
route state.

Hits are candidate evidence only. Detector hits are not filing proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-permissionless-route-setter-fire25"
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
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b")
_BRIDGE_CONTEXT_RE = re.compile(
    r"\b(?:bridge|crosschain|crossChain|cross[-_ ]?chain|gateway|route|"
    r"router|receiver|adapter|endpoint|channel|lane|peer|remote|dispatch|"
    r"message|packet|proof|root|commitment|relay|relayer)\b",
    re.IGNORECASE,
)
_ROUTE_SETTER_NAME_RE = re.compile(
    r"^(?:set|configure|register|initialize|init|setup|add|update|migrate)"
    r"[A-Za-z0-9_]*(?:Route|Routes|Receiver|Receivers|Endpoint|Endpoints|"
    r"Adapter|Adapters|Channel|Channels|Lane|Lanes|Peer|Remote|Gateway|"
    r"Bridge|Tunnel|Messenger|Router)$"
    r"|^(?:setBridgeRoute|setReceiver|setEndpoint|setAdapter|setChannel|"
    r"setPeer|setTrustedRemote|configureRoute|registerRoute|registerPath)$",
    re.IGNORECASE,
)
_ROUTE_STATE_NAMES = (
    r"routes?|routeBy\w*|bridgeRoutes?|receivers?|receiverBy\w*|"
    r"endpoints?|endpointBy\w*|adapters?|adapterBy\w*|channels?|"
    r"channelBy\w*|lanes?|laneBy\w*|peers?|peerBy\w*|"
    r"trustedRemotes?|remoteReceivers?|remoteEndpoints?|remoteBridges?|"
    r"gatewayFor|bridgeFor|dispatcherFor|routerFor|messengerFor"
)
_ROUTE_WRITE_RE = re.compile(
    rf"\b(?:{_ROUTE_STATE_NAMES})\s*(?:\[[^\]]+\]\s*){{1,4}}"
    r"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*="
    rf"|\b(?:{_ROUTE_STATE_NAMES})\s*\.\s*"
    r"(?:push|add|set)\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_ROUTE_READ_RE = re.compile(
    rf"\b(?:{_ROUTE_STATE_NAMES})\s*(?:\[[^\]]+\]\s*){{1,4}}"
    r"|\broute\s*\.\s*(?:receiver|endpoint|adapter|channel|lane|peer|"
    r"gateway|dispatcher|router|messenger)"
    r"|\b(?:receiver|endpoint|adapter|channel|peer|gateway|dispatcher|router)"
    r"\s*=\s*route\.",
    re.IGNORECASE | re.DOTALL,
)
_AUTH_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|"
    r"onlyDeployer|onlyRole|onlyOperator|onlyManager|onlyConfigurator|"
    r"onlyTimelock|onlyProtocol|onlyBridgeAdmin|requires?Auth|auth|"
    r"authorized|isAuthorized|hasRole|_checkRole|_checkOwner|_authorize)\b"
    r"|\bonly[A-Za-z0-9_]*(?:Owner|Admin|Governance|Governor|Factory|"
    r"Deployer|Role|Operator|Manager|Configurator|Timelock|Protocol|"
    r"BridgeAdmin|Router)\b"
    r"|require\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^;{}]*(?:owner|admin|governance|governor|factory|deployer|operator|"
    r"manager|configurator|timelock|protocol|controller|routeAdmin)"
    r"|if\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^;{}]*(?:!=|==)[^;{}]*(?:owner|admin|governance|governor|factory|"
    r"deployer|operator|manager|configurator|timelock|protocol|controller|"
    r"routeAdmin)",
    re.IGNORECASE | re.DOTALL,
)
_PROOF_CONTEXT_RE = re.compile(
    r"\b(?:proof|proofs|stateRoot|messageRoot|receiptRoot|root|leaf|"
    r"commitment|messageHash|payloadHash|packetHash|proofRoot|proofDigest|"
    r"signature|attestation|MerkleProof|verifyProof|verifyMessage|"
    r"verifyRoot|verifyCommitment)\b",
    re.IGNORECASE,
)
_DISPATCH_OR_SETTLE_RE = re.compile(
    r"\b(?:dispatch|deliver|execute|relay|settle|consume|finalize|process|"
    r"sendMessage|forwardMessage|receiveMessage|lzReceive)\s*\("
    r"|\.call\s*(?:\{|\()"
    r"|\bI[A-Za-z0-9_]*(?:Endpoint|Receiver|Adapter|Gateway|Dispatcher|"
    r"Messenger|Bridge)\s*\(",
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


def _line_for(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _is_public_mutating(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _weak_route_setters(functions: list[FunctionSlice]) -> list[tuple[FunctionSlice, re.Match[str]]]:
    setters: list[tuple[FunctionSlice, re.Match[str]]] = []
    for fn in functions:
        if not _is_public_mutating(fn):
            continue
        text = _context(fn)
        if not _ROUTE_SETTER_NAME_RE.search(fn.name):
            continue
        if _AUTH_RE.search(text):
            continue
        write = _ROUTE_WRITE_RE.search(fn.body)
        if write is None:
            continue
        setters.append((fn, write))
    return setters


def _has_route_proof_or_dispatch_consumer(functions: list[FunctionSlice]) -> bool:
    for fn in functions:
        if not _is_public_mutating(fn):
            continue
        text = _context(fn)
        if not _ROUTE_READ_RE.search(text):
            continue
        if not _PROOF_CONTEXT_RE.search(text):
            continue
        if not _DISPATCH_OR_SETTLE_RE.search(text):
            continue
        return True
    return False


def _finding(file_path: str, fn: FunctionSlice, write: re.Match[str]) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=_line_for(fn, write),
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=fn.name,
        message=(
            "Public bridge route setter writes receiver, endpoint, adapter, "
            "or channel state without owner, admin, factory, protocol, or "
            "role binding while a later proof or dispatch path reads the "
            "same route state. Candidate evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    if not _BRIDGE_CONTEXT_RE.search(code):
        return []

    functions = _split_functions(code)
    setters = _weak_route_setters(functions)
    if not setters:
        return []
    if not _has_route_proof_or_dispatch_consumer(functions):
        return []

    findings: list[Finding] = []
    for fn, write in setters:
        findings.append(_finding(file_path, fn, write))
    return findings
