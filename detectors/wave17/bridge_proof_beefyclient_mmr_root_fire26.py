"""
bridge-proof-beefyclient-mmr-root-fire26

Solidity recall-lift detector for Snowbridge BEEFY clients that accept an
MMR root from a signed commitment or proof transcript and store or use that
root before a visible digest binds the root to the source chain, BEEFY client
identity, consensus domain, destination application, and validator-set identity.

This is candidate evidence only. It is source-backed by the Snowbridge
pre-fix BeefyClient sample for audit issue 7, where the Fiat-Shamir transcript
fed root acceptance without the protocol domain and validator-set id/length.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-proof-beefyclient-mmr-root-fire26"
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

_BEEFY_ROOT_CONTEXT_RE = re.compile(
    r"\b(?:BEEFY|BeefyClient|MMR|MMRRoot|latestMMRRoot|NewMMRRoot|"
    r"Commitment|ValidatorSetState|validatorSet|Fiat.?Shamir|bitfield|"
    r"authoritySet|payloadID|MMR_ROOT_ID)\b",
    re.IGNORECASE,
)
_ROOT_ACCEPT_RE = re.compile(
    r"\b(?:ensureProvidesMMRRoot\s*\(|MMR_ROOT_ID|payloadID\s*==\s*MMR_ROOT_ID|"
    r"bytes32\s+\w*(?:MMR)?Root\s*=\s*[^;{}]*(?:commitment|payload|proof|digest))",
    re.IGNORECASE | re.DOTALL,
)
_ROOT_SINK_RE = re.compile(
    r"\b(?:latestMMRRoot|verifiedMMRRoot|acceptedMMRRoot|trustedMMRRoot|"
    r"rootByClient|mmrRootByClient)\s*(?:\[[^\]]+\])?\s*="
    r"|emit\s+NewMMRRoot\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_PROOF_ACCEPT_RE = re.compile(
    r"\b(?:verifyFiatShamirCommitment|verifyCommitment|verifyMMRLeafProof|"
    r"MMRProof\s*\.\s*verifyLeafProof|ECDSA\s*\.\s*recover|"
    r"validateTicket|isValidatorInSet)\s*\(",
    re.IGNORECASE,
)
_FIAT_OR_SUBSET_RE = re.compile(
    r"\b(?:Fiat.?Shamir|verifyFiatShamirCommitment|createFiatShamirHash|"
    r"fiatShamirFinalBitfield|Bitfield\.subsample)\b",
    re.IGNORECASE,
)
_HASH_EXPR_RE = re.compile(
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,1800}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_SAFE_HELPER_RE = re.compile(
    r"\b(?:bindBeefyMMRRootDomain|bindBeefyClientDomain|"
    r"domainBoundMMRRoot|domainBoundRootDigest|verifyDomainBoundMMRRoot|"
    r"verifyDomainBoundBeefyRoot|rootAcceptanceDigest)\s*\(",
    re.IGNORECASE,
)
_ROOT_MATERIAL_RE = re.compile(
    r"\b(?:newMMRRoot|mmrRoot|latestMMRRoot|MMR_ROOT_ID|root|commitmentHash|"
    r"commitment|leafHash|payload)\b",
    re.IGNORECASE,
)

_DOMAIN_GROUP_PATTERNS = (
    (
        "source_chain",
        re.compile(
            r"\b(?:source|src|origin|relay|polkadot|kusama)\w*"
            r"(?:ChainId|ChainID|Chain|Domain|DomainId|Network|ParaId|Parachain)\b"
            r"|\b(?:relayChain|sourceChainId|originChainId)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "beefy_client",
        re.compile(
            r"\b(?:beefyClientId|clientId|clientID|lightClientId|"
            r"validatorSetID|validatorSetId|authoritySetID|authoritySetId|"
            r"vset\.id|currentValidatorSet\.id|nextValidatorSet\.id)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "consensus_domain",
        re.compile(
            r"\b(?:BEEFY_MMR_ROOT_DOMAIN|BEEFY_CLIENT_DOMAIN|CONSENSUS_DOMAIN|"
            r"FIAT_SHAMIR_DOMAIN_ID|PROTOCOL_DOMAIN|TRANSCRIPT_DOMAIN|"
            r"domainSeparator|domainId|domain_id|DST)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_app",
        re.compile(
            r"\b(?:destinationApplication|destinationApp|destinationBridge|"
            r"destinationAdapter|applicationDomain|targetApplication|"
            r"address\s*\(\s*this\s*\)|block\.chainid)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "validator_identity",
        re.compile(
            r"\b(?:vset\.root|vset\.length|validatorSetRoot|validatorSetLength|"
            r"validatorSetLen|currentValidatorSet\.root|currentValidatorSet\.length|"
            r"nextValidatorSet\.root|nextValidatorSet\.length|authoritySetRoot|"
            r"authoritySetLen|authoritySetLength)\b",
            re.IGNORECASE,
        ),
    ),
)
_REQUIRED_GROUPS = {
    "source_chain",
    "beefy_client",
    "consensus_domain",
    "destination_app",
    "validator_identity",
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


def _first_root_sink(fn: FunctionSlice) -> re.Match[str] | None:
    return _ROOT_SINK_RE.search(fn.body)


def _is_candidate_function(fn: FunctionSlice) -> bool:
    text = _context(fn)
    if not _PUBLIC_HEADER_RE.search(fn.header):
        return False
    if not _BEEFY_ROOT_CONTEXT_RE.search(text):
        return False
    if not _FIAT_OR_SUBSET_RE.search(text):
        return False
    if not _ROOT_ACCEPT_RE.search(text):
        return False
    if not _PROOF_ACCEPT_RE.search(text):
        return False
    return _first_root_sink(fn) is not None


def _hash_has_full_root_domain_binding(expr: str) -> bool:
    if not _ROOT_MATERIAL_RE.search(expr):
        return False
    return _REQUIRED_GROUPS.issubset(_domain_groups(expr))


def _has_domain_bound_root_before_sink(fn: FunctionSlice) -> bool:
    sink = _first_root_sink(fn)
    if sink is None:
        return False
    prefix = fn.body[:sink.start()]

    for match in _HASH_EXPR_RE.finditer(prefix):
        if _hash_has_full_root_domain_binding(match.group("expr")):
            return True

    return bool(_SAFE_HELPER_RE.search(prefix))


def _first_acceptance(fn: FunctionSlice) -> re.Match[str] | None:
    return _PROOF_ACCEPT_RE.search(fn.body)


def _missing_groups_before_sink(fn: FunctionSlice) -> list[str]:
    sink = _first_root_sink(fn)
    prefix = fn.body if sink is None else fn.body[:sink.start()]
    best: set[str] = set()
    for match in _HASH_EXPR_RE.finditer(prefix):
        expr = match.group("expr")
        if _ROOT_MATERIAL_RE.search(expr):
            groups = _domain_groups(expr)
            if len(groups) > len(best):
                best = groups
    return sorted(_REQUIRED_GROUPS - best)


def _finding(file_path: str, line: int, function: str, missing: list[str]) -> Finding:
    missing_text = ", ".join(missing) if missing else "BEEFY root domain"
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "BEEFY/MMR root acceptance reaches a root storage or root-use sink "
            f"before the verified root digest binds {missing_text}. "
            "Candidate evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _is_candidate_function(fn):
            continue
        if _has_domain_bound_root_before_sink(fn):
            continue
        accept = _first_acceptance(fn)
        line = fn.body_line if accept is None else _line_for(fn, accept)
        findings.append(_finding(file_path, line, fn.name, _missing_groups_before_sink(fn)))
    return findings
