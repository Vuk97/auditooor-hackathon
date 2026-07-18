"""
bridge-digest-domain-fire33

Solidity recall-lift detector for bridge verifier paths that derive the
accepted proof digest from proof, root, nonce, or message material while
omitting visible bridge-domain fields such as source chain, destination chain,
receiver, adapter, endpoint, lane, or application domain.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:57361adac683c0c7
- context_pack_hash: 57361adac683c0c7f40a2f345b94c4172fe41a09373a05ca2cf8fae67d1b1dab
- source refs:
  - reports/detector_lift_fire32_20260605/post_priorities_all.md
  - reference/patterns.dsl/bridge-proof-domain-bypass-verifier-digest-omits-domain.yaml
  - reference/patterns.dsl/bridge-commitment-transcript-no-domain-separator.yaml
  - reference/patterns.dsl/bridge-replay-key-omits-chain-domain.yaml
- attack_class: bridge-proof-domain-bypass
- verification_tier: tier-3-synthetic-taxonomy-anchored

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-digest-domain-fire33"
DETECTOR_SEVERITY_DEFAULT = "High"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
COVERAGE_CLAIM = "detector_fixture_smoke_only"
PROMOTION_ALLOWED = False
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"


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
    line: int
    body_line: int


_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b")
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b")

_BRIDGE_CONTEXT_RE = re.compile(
    r"\b(?:bridge|crossChain|crosschain|cross[-_ ]?chain|gateway|portal|"
    r"messenger|mailbox|endpoint|adapter|adaptor|relayer|relay|router|"
    r"lane|channel|route|proof|root|commitment|receipt|nonce|domain|chain|"
    r"application|packet|payload|message|finality|validatorSet|validator[-_ ]?set|"
    r"transcript|digest|challenge|processed|consumed)\b",
    re.IGNORECASE,
)
_ENTRY_NAME_RE = re.compile(
    r"(?i)(verify|process|consume|finalize|prove|relay|submit|derive|create|"
    r"compute|receive|execute).*(proof|message|commitment|digest|leaf|"
    r"transcript|hash|challenge|header|packet|route|bridge)?"
)
_PROOF_MATERIAL_RE = re.compile(
    r"\b(?:proof|proofRoot|messageRoot|stateRoot|receiptRoot|exportRoot|root|"
    r"rootHash|rootDigest|commitment|commitmentHash|leaf|leafHash|payloadHash|"
    r"payload|messageHash|message|messageBody|receipt|packet|packetHash|"
    r"nonce|sequence|seq|header|bitFieldHash|validatorSetRoot|signature|"
    r"ballot|transcript)\b",
    re.IGNORECASE,
)
_HASH_ASSIGN_RE = re.compile(
    r"\b(?:bytes32\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*"
    r"(?:Digest|Hash|Root|Leaf|Challenge|Transcript|Id|ID))\s*=\s*"
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,3200}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_HASH_EXPR_RE = re.compile(
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,3200}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_VERIFY_CALL_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"(?:verify|verifyProof|verifyMessage|verifyDigest|verifyRoot|"
    r"verifyCommitment|isValidProof|checkProof|prove|recover|"
    r"isValidSignatureNow|processProof)\s*\((?P<args>[^;{}]{0,1800})\)|"
    r"\becrecover\s*\((?P<ecrecover_args>[^;{}]{0,1800})\)"
    r")"
)
_SINK_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:processed|consumed|used|seen|executed|delivered|claimed|"
    r"finalized|accepted)[A-Za-z0-9_]*\s*\[[^\]]+\]\s*=\s*(?:true|1)|"
    r"\b(?:dispatch|deliver|execute|handle|route|apply|receiveMessage|"
    r"onMessage|onBridgeMessage|processMessage|settle|release|claim|"
    r"mint|unlock|finalize)\s*\(|"
    r"\.\s*(?:call|delegatecall|functionCall|safeTransfer|transfer)"
    r"\s*(?:\{|\()"
    r")"
)
_SAFE_HELPER_RE = re.compile(
    r"\b(?:domainBoundBridgeDigest|domainBoundProofDigest|"
    r"hashDomainBoundBridgeMessage|hashDomainBoundProof|"
    r"hashCrossChainMessage|bindBridgeDomain|bindProofDomain|"
    r"verifyDomainBound[A-Za-z0-9_]*|_hashTypedDataV4|"
    r"domainSeparator|_domainSeparatorV4)\s*\(",
    re.IGNORECASE,
)
_TRUSTED_CALLER_RE = re.compile(
    r"(?is)\b(?:onlyEndpoint|onlyMailbox|onlyBridge|onlyMessenger|"
    r"onlyRelayer|onlyRouter|onlyOperator|onlyOwner|onlyAdmin)\b|"
    r"require\s*\(\s*msg\.sender\s*==\s*\w*(?:Endpoint|Mailbox|Bridge|"
    r"Messenger|Relayer|Router|Operator|Admin)\b"
)
_CANONICAL_BASE_RE = re.compile(
    r"\b(?:NonblockingLzApp|CCIPReceiver|AxelarExecutable|"
    r"AbstractMessageIdAuth|CrossDomainOwnable|IMessageRecipient)\b",
    re.IGNORECASE,
)
_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")

_DOMAIN_GROUP_PATTERNS = (
    (
        "source_chain",
        re.compile(
            r"\b(?:source|src|origin|remote|from)\w*"
            r"(?:ChainId|ChainID|ChainSelector|Selector|Chain|Domain|"
            r"DomainId|DomainID|NetworkId|Eid|EID)\b|"
            r"\b(?:srcEid|_srcEid|sourceChainSelector)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_chain",
        re.compile(
            r"\b(?:destination|dest|dst|target|local|to)\w*"
            r"(?:ChainId|ChainID|ChainSelector|Selector|Chain|Domain|"
            r"DomainId|DomainID|NetworkId|Eid|EID)\b|"
            r"\b(?:dstEid|localEid|block\s*\.\s*chainid)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "receiver",
        re.compile(
            r"\b(?:receiver|recipient|targetReceiver|targetRecipient|"
            r"destinationReceiver|localReceiver|receiverContract|"
            r"targetContract|destinationContract|beneficiary|to)\b|"
            r"\baddress\s*\(\s*this\s*\)",
            re.IGNORECASE,
        ),
    ),
    (
        "adapter",
        re.compile(
            r"\b(?:source|src|origin|remote|destination|dest|dst|target|"
            r"local)?\w*(?:Adapter|Adaptor|AdapterAddress|AdaptorAddress)"
            r"\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "source_endpoint",
        re.compile(
            r"\b(?:source|src|origin|remote|from|trusted)\w*"
            r"(?:BridgeEndpoint|Endpoint|Bridge|Gateway|Messenger|Mailbox)"
            r"\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_endpoint",
        re.compile(
            r"\b(?:destination|dest|dst|target|to|local)\w*"
            r"(?:BridgeEndpoint|Endpoint|Bridge|Gateway|Messenger|Mailbox)"
            r"\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "lane_or_channel",
        re.compile(
            r"\b(?:channel|channelId|channelID|lane|laneId|laneID|route|"
            r"routeId|routeID|port|portId|paraId|parachain|topic|topicId)"
            r"\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "application_domain",
        re.compile(
            r"\b(?:application|app|receiver|export)\w*"
            r"(?:Domain|DomainId|DomainID|Namespace|AppId|AppID|Id|ID)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "validator_set",
        re.compile(
            r"\b(?:validatorSetID|validatorSetId|validatorSetLen|"
            r"validatorSetLength|validatorSetRoot|authoritySetID|"
            r"authoritySetId|vset\.id|vset\.length|currentSet\.id|"
            r"currentSet\.length|currentValidatorSet\.id|"
            r"currentValidatorSet\.length)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "protocol_version",
        re.compile(
            r"\b(?:version|versionTag|routeVersion|proofVersion|isV1|isV2|"
            r"exportedCommitment|FIAT_SHAMIR_DOMAIN_ID|DOMAIN_ID)\b",
            re.IGNORECASE,
        ),
    ),
)
_GROUP_LABELS = {
    "source_chain": "source chain",
    "destination_chain": "destination chain",
    "receiver": "receiver",
    "adapter": "adapter",
    "source_endpoint": "source endpoint",
    "destination_endpoint": "destination endpoint",
    "lane_or_channel": "lane or channel id",
    "application_domain": "application domain",
    "validator_set": "validator-set identity",
    "protocol_version": "protocol version or domain tag",
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
        line = source.count("\n", 0, match.start()) + 1
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, line=line, body_line=body_line))
        pos = end_pos
    return out


def _context(fn: FunctionSlice) -> str:
    return f"{fn.name}\n{fn.header}\n{fn.body}"


def _line_for(fn: FunctionSlice, match: re.Match[str] | None) -> int:
    if match is None:
        return fn.line
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _domain_groups(text: str) -> set[str]:
    return {name for name, pattern in _DOMAIN_GROUP_PATTERNS if pattern.search(text)}


def _hash_assignments_before(body: str, pos: int) -> dict[str, str]:
    assignments: dict[str, str] = {}
    for match in _HASH_ASSIGN_RE.finditer(body[:pos]):
        assignments[match.group("name")] = match.group("expr")
    return assignments


def _is_callable(fn: FunctionSlice) -> bool:
    return bool(_CALLABLE_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _has_bridge_digest_verifier_shape(fn: FunctionSlice) -> bool:
    text = _context(fn)
    if not _is_callable(fn):
        return False
    if _CANONICAL_BASE_RE.search(text) or _TRUSTED_CALLER_RE.search(text):
        return False
    if not (_ENTRY_NAME_RE.search(fn.name) or _BRIDGE_CONTEXT_RE.search(text)):
        return False
    if not _BRIDGE_CONTEXT_RE.search(text):
        return False
    if len(_domain_groups(text)) < 2:
        return False
    if _PROOF_MATERIAL_RE.search(text) is None:
        return False
    if _VERIFY_CALL_RE.search(fn.body) is None:
        return False
    if _SINK_RE.search(fn.body) is None:
        return False
    return _HASH_EXPR_RE.search(fn.body) is not None


def _accepted_digest_exprs(fn: FunctionSlice, verify: re.Match[str]) -> list[str]:
    args = verify.group("args") or verify.group("ecrecover_args") or ""
    out: list[str] = []
    out.extend(match.group("expr") for match in _HASH_EXPR_RE.finditer(args))

    assignments = _hash_assignments_before(fn.body, verify.start())
    for ident_match in _IDENT_RE.finditer(args):
        expr = assignments.get(ident_match.group(0))
        if expr:
            out.append(expr)
    return out


def _unsafe_digest(fn: FunctionSlice) -> tuple[list[str], re.Match[str] | None]:
    visible = _domain_groups(_context(fn))
    if not visible:
        return [], None

    for verify in _VERIFY_CALL_RE.finditer(fn.body):
        if not _SINK_RE.search(fn.body[verify.end():]):
            continue
        for expr in _accepted_digest_exprs(fn, verify):
            if not _PROOF_MATERIAL_RE.search(expr):
                continue
            if _SAFE_HELPER_RE.search(expr):
                continue
            bound = _domain_groups(expr)
            missing = sorted(visible - bound)
            if missing:
                return missing, verify
    return [], None


def _finding(file_path: str, fn: FunctionSlice, match: re.Match[str], missing: list[str]) -> Finding:
    labels = ", ".join(_GROUP_LABELS[item] for item in missing)
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=_line_for(fn, match),
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=fn.name,
        message=(
            f"Bridge verifier accepted digest omits {labels}. The function "
            "hashes proof, root, nonce, or message material and verifies that "
            "digest, but the digest preimage does not bind every visible "
            "source, destination, receiver, adapter, endpoint, lane, or "
            "application-domain field used around delivery. NOT_SUBMIT_READY: "
            "detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _has_bridge_digest_verifier_shape(fn):
            continue
        missing, match = _unsafe_digest(fn)
        if not missing or match is None:
            continue
        findings.append(_finding(file_path, fn, match, missing))
    return findings


__all__ = [
    "scan",
    "Finding",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
]
