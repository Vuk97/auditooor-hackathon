"""
bridge-proof-snowbridge-adapter-fire25

Solidity recall-lift detector for Snowbridge-style bridge adapters that accept
an inbound or outbound message proof and then dispatch or consume the message
while the verified digest omits one of the adapter replay domain fields:
chain id, local adapter address, source bridge endpoint, channel, or
destination bridge endpoint.

This is candidate evidence only. A hit requires visible adapter/proof context,
all five replay-domain groups in scope, a proof acceptance step, and a
dispatch or consume sink. A proof digest or explicit helper that binds all
five groups before the sink suppresses the hit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-proof-snowbridge-adapter-fire25"
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
_ADAPTER_CONTEXT_RE = re.compile(
    r"\b(?:snowbridge|bridge|gateway|crosschain|crossChain|cross[-_ ]?chain|"
    r"adaptor|adapter|endpoint|channel|lane|proof|root|message|commitment|"
    r"inbound|outbound|dispatch|consume|relay)\b",
    re.IGNORECASE,
)
_PROOF_ACCEPT_RE = re.compile(
    r"\b(?:verify|verifyProof|verifyMessage|verifyMerkleProof|verifyRoot|"
    r"verifyCommitment|isValidProof|MerkleProof\s*\.\s*verify|"
    r"[A-Za-z0-9_]*Proof\s*\.\s*verify[A-Za-z0-9_]*|"
    r"require\s*\([^;{}]*(?:proof|root|leaf|digest|messageRoot|messageHash))",
    re.IGNORECASE | re.DOTALL,
)
_PROOF_MATERIAL_RE = re.compile(
    r"\b(?:proof|root|messageRoot|stateRoot|receiptRoot|leaf|leafHash|"
    r"digest|commitment|messageHash|messageId|messageID|payloadHash|nonce)\b",
    re.IGNORECASE,
)
_SINK_RE = re.compile(
    r"(?:"
    r"\b(?:dispatch|execute|handle|relay|receiveMessage|sendMessage|"
    r"consumeMessage|processMessage)\s*\(|"
    r"\bI[A-Za-z0-9_]*(?:Adapter|Adaptor|Endpoint|Gateway|Messenger)\s*"
    r"\([^;{}]*\)\s*\.\s*(?:dispatch|execute|handle|relay|receiveMessage|"
    r"sendMessage)\s*\(|"
    r"\b(?:destination|dest|dst|target|remote|local|source)?"
    r"(?:Adapter|Adaptor|Endpoint|Gateway|Messenger)[A-Za-z0-9_]*\s*\."
    r"(?:dispatch|execute|handle|relay|receiveMessage|sendMessage|call)\s*\(|"
    r"\b(?:processed|consumed|used|delivered|received|executed|relayed)"
    r"[A-Za-z0-9_]*\s*\[[^\]]+\]\s*=\s*true\b|"
    r"\b(?:processed|consumed|used|delivered|received|executed|relayed)"
    r"[A-Za-z0-9_]*\s*\.\s*(?:add|set)\s*\("
    r")",
    re.IGNORECASE | re.DOTALL,
)
_HASH_EXPR_RE = re.compile(
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,1400}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_SAFE_HELPER_RE = re.compile(
    r"\b(?:bindSnowbridgeAdapterDomain|bindAdapterProofDomain|"
    r"domainBoundAdapterDigest|domainBoundAdapterLeaf|"
    r"verifyDomainBoundAdapter[A-Za-z0-9_]*)\s*\(",
    re.IGNORECASE,
)

_DOMAIN_GROUP_PATTERNS = (
    (
        "chain_id",
        re.compile(
            r"\b(?:source|src|origin|remote|from|destination|dest|dst|target|"
            r"local|to)?\w*(?:ChainId|ChainID|Chain|Domain|DomainId|DomainID|"
            r"NetworkId|Eid)\b|\b(?:chainid|block\.chainid)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "adapter_address",
        re.compile(
            r"\b(?:local|destination|dest|dst|target|remote|source|src)?"
            r"\w*(?:Adapter|Adaptor|AdapterAddress|AdaptorAddress)\w*\b|"
            r"\baddress\s*\(\s*this\s*\)",
            re.IGNORECASE,
        ),
    ),
    (
        "source_endpoint",
        re.compile(
            r"\b(?:source|src|origin|remote|from|trusted)\w*"
            r"(?:BridgeEndpoint|Endpoint|Bridge|Gateway|Messenger|Mailbox)\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "channel",
        re.compile(
            r"\b(?:channel|channelId|channelID|lane|laneId|laneID|route|"
            r"routeId|routeID|paraId|paraID|parachain)\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_endpoint",
        re.compile(
            r"\b(?:destination|dest|dst|target|to|local)\w*"
            r"(?:BridgeEndpoint|Endpoint|Bridge|Gateway|Messenger|Mailbox)\w*\b",
            re.IGNORECASE,
        ),
    ),
)
_REQUIRED_GROUPS = {
    "chain_id",
    "adapter_address",
    "source_endpoint",
    "channel",
    "destination_endpoint",
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
    if not _ADAPTER_CONTEXT_RE.search(text):
        return False
    if not _REQUIRED_GROUPS.issubset(_domain_groups(text)):
        return False
    if not _PROOF_ACCEPT_RE.search(text):
        return False
    return bool(_SINK_RE.search(text))


def _hash_has_full_domain_binding(expr: str) -> bool:
    if not _PROOF_MATERIAL_RE.search(expr):
        return False
    return _REQUIRED_GROUPS.issubset(_domain_groups(expr))


def _first_sink(fn: FunctionSlice) -> re.Match[str] | None:
    return _SINK_RE.search(fn.body)


def _has_domain_bound_proof_before_sink(fn: FunctionSlice) -> bool:
    sink = _first_sink(fn)
    if sink is None:
        return False
    prefix = fn.body[:sink.start()]

    for match in _HASH_EXPR_RE.finditer(prefix):
        if _hash_has_full_domain_binding(match.group("expr")):
            return True

    return bool(_SAFE_HELPER_RE.search(prefix))


def _first_acceptance(fn: FunctionSlice) -> re.Match[str] | None:
    return _PROOF_ACCEPT_RE.search(fn.body)


def _missing_groups_before_sink(fn: FunctionSlice) -> list[str]:
    sink = _first_sink(fn)
    prefix = fn.body if sink is None else fn.body[:sink.start()]
    best: set[str] = set()
    for match in _HASH_EXPR_RE.finditer(prefix):
        expr = match.group("expr")
        if _PROOF_MATERIAL_RE.search(expr):
            groups = _domain_groups(expr)
            if len(groups) > len(best):
                best = groups
    if not best:
        best = set()
    return sorted(_REQUIRED_GROUPS - best)


def _finding(file_path: str, line: int, function: str, missing: list[str]) -> Finding:
    missing_text = ", ".join(missing) if missing else "adapter replay domain"
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "Snowbridge-style adapter accepts a bridge message proof before "
            f"the verified digest binds {missing_text}. Candidate evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _is_candidate_function(fn):
            continue
        if _has_domain_bound_proof_before_sink(fn):
            continue
        accept = _first_acceptance(fn)
        line = fn.body_line if accept is None else _line_for(fn, accept)
        findings.append(_finding(file_path, line, fn.name, _missing_groups_before_sink(fn)))
    return findings
