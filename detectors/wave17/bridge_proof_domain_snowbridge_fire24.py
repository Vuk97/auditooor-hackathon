"""
bridge-proof-domain-snowbridge-fire24

Solidity recall-lift detector for Snowbridge-style bridge proof consumers that
verify a BEEFY/MMR, Merkle, or commitment proof and then dispatch through an
adapter while the verified leaf or digest omits the source chain, source bridge
instance, lane/channel, parachain, and destination adapter domain.

This is candidate evidence only. It requires proof acceptance plus adapter
dispatch in the same function, visible Snowbridge or bridge proof terminology,
and visible domain fields that are not all bound into a proof leaf/digest before
dispatch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-proof-domain-snowbridge-fire24"
DETECTOR_SEVERITY_DEFAULT = "High"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
COVERAGE_CLAIM = "detector_fixture_smoke_only"
PROMOTION_ALLOWED = False


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
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b")
_SNOWBRIDGE_CONTEXT_RE = re.compile(
    r"\b(?:snowbridge|beefy|mmr|mmrleaf|parachain|paraId|paraID|"
    r"encodedParaID|BridgeHub|xcm|bridge|gateway|crossChain|cross[-_ ]?chain|"
    r"proof|commitment|adapter|adaptor)\b",
    re.IGNORECASE,
)
_PROOF_ACCEPT_RE = re.compile(
    r"\b(?:verifyCommitment|verifyMMRLeafProof|verifyProof|verifyMessage|"
    r"verifyRoot|verifyLeafProof|MerkleProof\s*\.\s*verify|"
    r"[A-Za-z0-9_]*Proof\s*\.\s*verify[A-Za-z0-9_]*|"
    r"require\s*\([^;{}]*(?:proof|root|leaf|commitment|messageCommitment))",
    re.IGNORECASE | re.DOTALL,
)
_PROOF_MATERIAL_RE = re.compile(
    r"\b(?:proof|root|mmrRoot|leaf|leafHash|proofLeaf|digest|commitment|"
    r"messageCommitment|payloadHash|messageHash|header|parachainHead)\b",
    re.IGNORECASE,
)
_ADAPTER_DISPATCH_RE = re.compile(
    r"(?:\bI[A-Za-z0-9_]*(?:Adapter|Adaptor|Gateway|Messenger)\s*\([^;{}]*\)"
    r"\s*\.\s*(?:dispatch|execute|handle|relay|receiveMessage|sendMessage)\s*\(|"
    r"\b(?:destination|dest|dst|target|local|remote)?(?:Adapter|Adaptor|Gateway|Messenger)"
    r"[A-Za-z0-9_]*\s*\.\s*(?:dispatch|execute|handle|relay|receiveMessage|sendMessage)\s*\(|"
    r"\b(?:destinationAdapter|destAdapter|dstAdapter|targetAdapter|localAdapter)"
    r"\s*\.\s*call\s*\(|"
    r"\b(?:destinationAdapter|destAdapter|dstAdapter|targetAdapter|localAdapter)"
    r"\s*\.call\s*\()",
    re.IGNORECASE | re.DOTALL,
)
_HASH_EXPR_RE = re.compile(
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,1400}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_STRONG_DOMAIN_GUARD_RE = re.compile(
    r"\b(?:WrongSource|WrongDestination|WrongBridge|WrongChannel|WrongLane|"
    r"WrongParachain|WrongAdapter|InvalidSource|InvalidDestination|"
    r"InvalidBridge|InvalidChannel|InvalidParachain|InvalidAdapter)\b",
    re.IGNORECASE,
)
_SAFE_PROOF_HELPER_RE = re.compile(
    r"\b(?:bindSnowbridgeDomain|bindProofDomain|domainBoundLeaf|"
    r"domainBoundDigest|verifyDomainBound[A-Za-z0-9_]*)\s*\(",
    re.IGNORECASE,
)

_DOMAIN_GROUP_PATTERNS = (
    (
        "source_chain",
        re.compile(
            r"\b(?:source|src|origin|remote|from)\w*(?:ChainId|Chain|Domain|"
            r"DomainId|NetworkId|Eid)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "source_bridge",
        re.compile(
            r"\b(?:source|src|origin|remote|trusted)\w*(?:Bridge|Gateway|"
            r"BridgeInstance|BridgeAddress|GatewayAddress)\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "lane_channel",
        re.compile(
            r"\b(?:lane|laneId|channel|channelId|route|routeId|inboundChannel|"
            r"outboundChannel)\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "parachain",
        re.compile(
            r"\b(?:parachain|paraId|paraID|encodedParaID|bridgeHubPara|"
            r"bridgeHubParachain)\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_adapter",
        re.compile(
            r"\b(?:destination|dest|dst|target|local)\w*(?:Adapter|Adaptor|"
            r"Gateway|Messenger)\w*\b",
            re.IGNORECASE,
        ),
    ),
)
_REQUIRED_GROUPS = {
    "source_chain",
    "source_bridge",
    "lane_channel",
    "parachain",
    "destination_adapter",
}


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


def _line_for(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _context(fn: FunctionSlice) -> str:
    return f"{fn.name}\n{fn.header}\n{fn.body}"


def _domain_groups(text: str) -> set[str]:
    return {name for name, pattern in _DOMAIN_GROUP_PATTERNS if pattern.search(text)}


def _is_candidate_function(fn: FunctionSlice) -> bool:
    text = _context(fn)
    if not _PUBLIC_HEADER_RE.search(fn.header):
        return False
    if not _SNOWBRIDGE_CONTEXT_RE.search(text):
        return False
    if not _REQUIRED_GROUPS.issubset(_domain_groups(text)):
        return False
    if not _PROOF_ACCEPT_RE.search(text):
        return False
    return bool(_ADAPTER_DISPATCH_RE.search(text))


def _hash_has_full_domain_binding(expr: str) -> bool:
    if not _PROOF_MATERIAL_RE.search(expr):
        return False
    return _REQUIRED_GROUPS.issubset(_domain_groups(expr))


def _has_domain_bound_proof_before_dispatch(fn: FunctionSlice) -> bool:
    dispatch = _ADAPTER_DISPATCH_RE.search(fn.body)
    if dispatch is None:
        return False
    prefix = fn.body[:dispatch.start()]

    for match in _HASH_EXPR_RE.finditer(prefix):
        if _hash_has_full_domain_binding(match.group("expr")):
            return True

    if _SAFE_PROOF_HELPER_RE.search(prefix):
        return True

    # Named error checks alone are not sufficient unless the proof leaf or a
    # proof-domain helper also binds the proof material.
    return False


def _first_acceptance(fn: FunctionSlice) -> re.Match[str] | None:
    return _PROOF_ACCEPT_RE.search(fn.body)


def _finding(file_path: str, line: int, function: str) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "Snowbridge-style bridge proof dispatch accepts proof material "
            "without binding source chain, source bridge, lane/channel, "
            "parachain, and destination adapter into the verified domain. "
            "Candidate evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _is_candidate_function(fn):
            continue
        if _has_domain_bound_proof_before_dispatch(fn):
            continue
        accept = _first_acceptance(fn)
        line = fn.body_line if accept is None else _line_for(fn, accept)
        findings.append(_finding(file_path, line, fn.name))
    return findings
