"""
bridge-merkle-leaf-domain-fire26

Regex-style Solidity detector for bridge Merkle or MMR proof consumers that
verify a leaf or accept a proof-derived root, then consume the proof result
while the verified leaf was not bound to the bridge replay domain.

This is candidate evidence only. It intentionally does not flag raw proof
libraries such as Snowbridge MMRProof or SubstrateMerkleProof unless a bridge
consumer sink is present after proof acceptance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-merkle-leaf-domain-fire26"
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
_BRIDGE_PROOF_CONTEXT_RE = re.compile(
    r"\b(?:bridge|gateway|crosschain|crossChain|cross[-_ ]?chain|snowbridge|"
    r"beefy|mmr|merkle|substrate|pallet|module|channel|lane|proof|root|"
    r"leaf|message|commitment|dispatch|relay)\b",
    re.IGNORECASE,
)
_PROOF_ACCEPT_RE = re.compile(
    r"\b(?:"
    r"MMRProof\s*\.\s*verifyLeafProof|"
    r"SubstrateMerkleProof\s*\.\s*verify|"
    r"MerkleProof\s*\.\s*(?:verify|processProof)|"
    r"verifyMMRLeafProof|"
    r"verifyMerkleProof|"
    r"verifyLeafProof|"
    r"verifyProof|"
    r"computeRoot"
    r")\s*\(",
    re.IGNORECASE,
)
_PROOF_MATERIAL_RE = re.compile(
    r"\b(?:leaf|leafHash|messageLeaf|proofLeaf|root|messageRoot|mmrRoot|"
    r"payloadHash|messageHash|commitment|messageCommitment|receipt|header)\b",
    re.IGNORECASE,
)
_CONSUME_SINK_RE = re.compile(
    r"(?:"
    r"\b(?:dispatch|execute|handle|relay|receiveMessage|sendMessage|"
    r"processMessage|consumeMessage|v2_dispatch|release|settle|mint|"
    r"unlock|finalize)\s*\(|"
    r"\b(?:processed|consumed|used|delivered|received|executed|relayed|"
    r"inboundNonce|messageConsumed|messageProcessed)[A-Za-z0-9_]*"
    r"\s*\[[^\]]+\]\s*=\s*(?:true|1)|"
    r"\b(?:processed|consumed|used|delivered|received|executed|relayed)"
    r"[A-Za-z0-9_]*\s*\.\s*(?:add|set)\s*\("
    r")",
    re.IGNORECASE | re.DOTALL,
)
_HASH_EXPR_RE = re.compile(
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,1800}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_SAFE_HELPER_RE = re.compile(
    r"\b(?:bindMerkleLeafDomain|bindMMRLeafDomain|bindBridgeLeafDomain|"
    r"domainBoundLeaf|domainBoundMerkleLeaf|domainBoundMMRLeaf|"
    r"hashLeafWithBridgeDomain|verifyDomainBoundMerkle|"
    r"verifyDomainBoundMMR|createDomainBoundLeaf)\s*\(",
    re.IGNORECASE,
)

_DOMAIN_GROUP_PATTERNS = (
    (
        "source_chain",
        re.compile(
            r"\b(?:source|src|origin|remote|from|trusted)\w*"
            r"(?:ChainId|ChainID|Chain|Domain|DomainId|DomainID|"
            r"NetworkId|Eid)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "bridge_endpoint",
        re.compile(
            r"\b(?:source|src|origin|remote|trusted|bridge|local|gateway)"
            r"\w*(?:Endpoint|Bridge|BridgeInstance|BridgeAddress|"
            r"Gateway|GatewayAddress|Messenger|Mailbox|Adapter|Adaptor)\w*\b|"
            r"\baddress\s*\(\s*this\s*\)",
            re.IGNORECASE,
        ),
    ),
    (
        "module_pallet",
        re.compile(
            r"\b(?:pallet|palletId|palletID|module|moduleId|moduleID|"
            r"bridgeHub|bridgeHubPara|parachain|paraId|paraID|"
            r"inboundQueue|outboundQueue|messageQueue)\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "channel",
        re.compile(
            r"\b(?:channel|channelId|channelID|lane|laneId|laneID|route|"
            r"routeId|routeID|topic|topicId|topicID)\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "message_nonce",
        re.compile(
            r"\b(?:nonce|messageNonce|messageID|messageId|sequence|seq|"
            r"inboundNonce|outboundNonce)\w*\b",
            re.IGNORECASE,
        ),
    ),
)
_REQUIRED_GROUPS = {
    "source_chain",
    "bridge_endpoint",
    "module_pallet",
    "channel",
    "message_nonce",
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


def _first_proof_acceptance(fn: FunctionSlice) -> re.Match[str] | None:
    return _PROOF_ACCEPT_RE.search(fn.body)


def _first_consumption_after(fn: FunctionSlice, proof: re.Match[str]) -> re.Match[str] | None:
    match = _CONSUME_SINK_RE.search(fn.body, proof.end())
    if match is not None:
        return match
    return None


def _is_candidate_function(fn: FunctionSlice) -> bool:
    text = _context(fn)
    if not _PUBLIC_HEADER_RE.search(fn.header):
        return False
    if not _BRIDGE_PROOF_CONTEXT_RE.search(text):
        return False
    if not _REQUIRED_GROUPS.issubset(_domain_groups(text)):
        return False
    proof = _first_proof_acceptance(fn)
    if proof is None:
        return False
    return _first_consumption_after(fn, proof) is not None


def _hash_has_full_leaf_domain(expr: str) -> bool:
    if not _PROOF_MATERIAL_RE.search(expr):
        return False
    return _REQUIRED_GROUPS.issubset(_domain_groups(expr))


def _prefix_through_proof(fn: FunctionSlice) -> str:
    proof = _first_proof_acceptance(fn)
    if proof is None:
        return fn.body
    return fn.body[:proof.end()]


def _has_domain_bound_leaf_before_proof(fn: FunctionSlice) -> bool:
    prefix = _prefix_through_proof(fn)
    for match in _HASH_EXPR_RE.finditer(prefix):
        if _hash_has_full_leaf_domain(match.group("expr")):
            return True
    return bool(_SAFE_HELPER_RE.search(prefix))


def _missing_groups_before_proof(fn: FunctionSlice) -> list[str]:
    prefix = _prefix_through_proof(fn)
    best: set[str] = set()
    for match in _HASH_EXPR_RE.finditer(prefix):
        expr = match.group("expr")
        if not _PROOF_MATERIAL_RE.search(expr):
            continue
        groups = _domain_groups(expr)
        if len(groups) > len(best):
            best = groups
    return sorted(_REQUIRED_GROUPS - best)


def _finding(file_path: str, line: int, function: str, missing: list[str]) -> Finding:
    missing_text = ", ".join(missing) if missing else "bridge leaf domain"
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "Bridge Merkle/MMR proof result is consumed after the verified "
            f"leaf omits {missing_text}. Candidate evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _is_candidate_function(fn):
            continue
        if _has_domain_bound_leaf_before_proof(fn):
            continue
        proof = _first_proof_acceptance(fn)
        line = fn.body_line if proof is None else _line_for(fn, proof)
        findings.append(_finding(file_path, line, fn.name, _missing_groups_before_proof(fn)))
    return findings
