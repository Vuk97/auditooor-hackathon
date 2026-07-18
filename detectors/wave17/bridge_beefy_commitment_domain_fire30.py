"""
bridge-beefy-commitment-domain-fire30.

Solidity recall-lift detector for Snowbridge BEEFY-style commitment
verification paths that accept a commitment or MMR root digest before the
checked commitment is bound to the destination domain, chain id, validator-set
identity, and application channel.

This is candidate evidence only. It is intentionally narrower than the older
Snowbridge adapter and MMR-root detectors: a hit needs BEEFY/MMR context,
commitment verification, a checked digest derived from commitment/root
material, and a root or commitment acceptance sink.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-beefy-commitment-domain-fire30"
DETECTOR_SEVERITY_DEFAULT = "High"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
COVERAGE_CLAIM = "detector_fixture_smoke_only"
PROMOTION_ALLOWED = False
VERIFICATION_TIER = "tier-2-verified-public-archive"


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

_BEEFY_PROTOCOL_RE = re.compile(
    r"\b(?:BEEFY|BeefyClient|MMR|MMRRoot|MMR_ROOT_ID|Fiat.?Shamir|"
    r"bitfield|validatorSet|ValidatorSet|authoritySet|commitmentHash)\b",
    re.IGNORECASE,
)
_COMMITMENT_CONTEXT_RE = re.compile(
    r"\b(?:commitment|commitmentHash|commitmentDigest|checkedCommitment|"
    r"rootDigest|MMRRoot|newMMRRoot|payloadID|MMR_ROOT_ID)\b",
    re.IGNORECASE,
)
_COMMITMENT_MATERIAL_RE = re.compile(
    r"\b(?:commitment|commitmentHash|commitmentDigest|checkedCommitment|"
    r"rootDigest|mmrRoot|newMMRRoot|MMR_ROOT_ID|payload|leaf|root|"
    r"bitFieldHash|validatorSetRoot|vsetRoot)\b",
    re.IGNORECASE,
)
_ACCEPT_RE = re.compile(
    r"\b(?P<callee>verifyCommitment|verifyFiatShamirCommitment|"
    r"verifyBeefyCommitment|verifySignedCommitment|verifyRootCommitment|"
    r"verifyMMRRootCommitment|ECDSA\s*\.\s*recover|recover)\s*\(\s*"
    r"(?P<arg>[A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)
_HASH_ASSIGN_RE = re.compile(
    r"\b(?:bytes32\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*"
    r"(?:Hash|Digest|Commitment|Root|Leaf|Challenge|Transcript))\s*=\s*"
    r"(?P<expr>(?:keccak256|sha256)\s*\([^;{}]{0,2200}\))",
    re.IGNORECASE | re.DOTALL,
)
_SINK_RE = re.compile(
    r"\b(?:latestMMRRoot|verifiedMMRRoot|acceptedMMRRoot|trustedMMRRoot|"
    r"latestBeefyRoot|acceptedRoot|commitmentAccepted|acceptedCommitments|"
    r"verifiedCommitments|processedCommitments)\s*(?:\[[^\]]+\])?\s*="
    r"|emit\s+NewMMRRoot\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_SAFE_HELPER_RE = re.compile(
    r"\b(?:bindBeefyCommitmentDomain|bindBeefyRootDomain|"
    r"domainBoundBeefyCommitment|domainBoundCommitmentDigest|"
    r"verifyDomainBoundBeefyCommitment|verifyDomainBoundCommitment|"
    r"rootAcceptanceDigest)\s*\(",
    re.IGNORECASE,
)

_DOMAIN_GROUP_PATTERNS = (
    (
        "destination_domain",
        re.compile(
            r"\b(?:destination|dest|dst|target|local)\w*"
            r"(?:Domain|DomainId|ChainDomain|BridgeDomain|NetworkId)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "chain_id",
        re.compile(
            r"\b(?:source|src|origin|relay|remote|destination|dest|dst|"
            r"target|local)?\w*(?:ChainId|ChainID|Chain|NetworkId|Eid)\b"
            r"|\b(?:block\.chainid|chainid|CHAIN_ID)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "validator_set_id",
        re.compile(
            r"\b(?:validatorSetID|validatorSetId|validatorSetLen|"
            r"validatorSetLength|validatorSetRoot|authoritySetID|"
            r"authoritySetId|authoritySetLen|authoritySetLength|"
            r"vset\.id|vset\.length|currentValidatorSet\.id|"
            r"currentValidatorSet\.length|currentValidatorSet\.root|"
            r"nextValidatorSet\.id|nextValidatorSet\.length|"
            r"nextValidatorSet\.root)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "application_channel",
        re.compile(
            r"\b(?:application|app|channel|lane|route|para|parachain)"
            r"\w*(?:Channel|ChannelId|Lane|LaneId|Route|RouteId|"
            r"AppId|Application|ApplicationId|ParaId|ParachainId)?\b",
            re.IGNORECASE,
        ),
    ),
)
_REQUIRED_GROUPS = {
    "destination_domain",
    "chain_id",
    "validator_set_id",
    "application_channel",
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


def _is_beefy_commitment_function(fn: FunctionSlice) -> bool:
    text = _context(fn)
    if not _PUBLIC_HEADER_RE.search(fn.header):
        return False
    if not _BEEFY_PROTOCOL_RE.search(text):
        return False
    if not _COMMITMENT_CONTEXT_RE.search(text):
        return False
    if _SINK_RE.search(fn.body) is None:
        return False
    return _ACCEPT_RE.search(fn.body) is not None


def _assignment_before(body: str, name: str, pos: int) -> str:
    found = ""
    for match in _HASH_ASSIGN_RE.finditer(body[:pos]):
        if match.group("name") == name:
            found = match.group("expr")
    return found


def _checked_expr_for_accept(fn: FunctionSlice, accept: re.Match[str]) -> str:
    arg = accept.group("arg")
    expr = _assignment_before(fn.body, arg, accept.start())
    if expr:
        return expr
    return arg


def _sink_after_accept(fn: FunctionSlice, pos: int) -> bool:
    return _SINK_RE.search(fn.body[pos:]) is not None


def _is_domain_bound_expr(expr: str) -> bool:
    if not _COMMITMENT_MATERIAL_RE.search(expr):
        return False
    return _REQUIRED_GROUPS.issubset(_domain_groups(expr))


def _missing_groups(expr: str) -> list[str]:
    return sorted(_REQUIRED_GROUPS - _domain_groups(expr))


def _unsafe_acceptance(fn: FunctionSlice) -> tuple[re.Match[str], list[str]] | None:
    for accept in _ACCEPT_RE.finditer(fn.body):
        if not _sink_after_accept(fn, accept.end()):
            continue
        prefix = fn.body[:accept.start()]
        if _SAFE_HELPER_RE.search(prefix):
            continue
        checked_expr = _checked_expr_for_accept(fn, accept)
        if not _COMMITMENT_MATERIAL_RE.search(checked_expr):
            continue
        if _is_domain_bound_expr(checked_expr):
            continue
        return accept, _missing_groups(checked_expr)
    return None


def _finding(file_path: str, line: int, function: str, missing: list[str]) -> Finding:
    missing_text = ", ".join(missing) if missing else "commitment domain"
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "BEEFY commitment verification accepts a commitment/root digest "
            f"before the checked commitment binds {missing_text}. "
            "Candidate evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _is_beefy_commitment_function(fn):
            continue
        unsafe = _unsafe_acceptance(fn)
        if unsafe is None:
            continue
        accept, missing = unsafe
        findings.append(_finding(file_path, _line_for(fn, accept), fn.name, missing))
    return findings
