"""
bridge-destination-commitment-domain-fire37

Solidity recall-lift detector for destination-side bridge settlement or proof
acceptance paths that expose source commitment, destination chain, receiver
domain, route id, or adapter id fields, then mark consumed, mint, release, or
execute a message before those fields are authenticated in the source proof or
settlement commitment.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:f4d2e1d5cdce68c4
- context_pack_hash: f4d2e1d5cdce68c48442ecdcc7a8f029fcf9efb0e11511c8f00371f9c304e88f
- source refs:
  - reports/detector_lift_fire36_20260605/post_priorities_solidity.md
  - reference/patterns.dsl/bridge-destination-settlement-unproven-source-commitment.yaml
  - detectors/wave17/bridge_proof_route_domain_fire36.py
  - reference/patterns.dsl/bridge-destination-settlement-unproven-source-fire9.yaml
- note: the brief also named detectors/wave17/bridge_destination_settlement_unproven_source_commitment.py, but that exact path is absent in this worktree.
- attack_class: bridge-proof-domain-bypass
- verification_tier: tier-3-synthetic-taxonomy-anchored

Domain field set: source commitment, destination chain, receiver domain, route id, or adapter id.

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-destination-commitment-domain-fire37"
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
_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_BRACKET_RE = re.compile(r"\[([^\]\n;{}]+)\]")

_BRIDGE_CONTEXT_RE = re.compile(
    r"\b(?:bridge|crossChain|crosschain|cross[-_ ]?chain|gateway|portal|"
    r"messenger|mailbox|endpoint|adapter|adaptor|relayer|relay|router|"
    r"destination|settlement|withdrawal|claim|escrow|proof|root|stateRoot|"
    r"messageRoot|acceptedRoot|sourceRoot|commitment|sourceCommitment|"
    r"messageHash|leaf|route|lane|channel|payload|message|processed|"
    r"consumed|finalized|claimed|settled)\b",
    re.IGNORECASE,
)
_ENTRY_NAME_RE = re.compile(
    r"(?i)(finalize|claim|release|settle|execute|process|complete|receive|"
    r"redeem|accept|deliver|consume).*(bridge|transfer|message|claim|"
    r"withdrawal|settlement|token|erc20|proof|commitment|source)?"
)
_PROOF_MATERIAL_RE = re.compile(
    r"\b(?:proof|merkleProof|stateProof|storageProof|proofRoot|acceptedRoot|"
    r"stateRoot|sourceRoot|messageRoot|root|rootHash|commitment|"
    r"sourceCommitment|commitmentHash|messageHash|leaf|leafHash|payloadHash|"
    r"payload|message|nonce|sequence|routeId|adapterId|signature|sig)\b",
    re.IGNORECASE,
)
_ROOT_ACCEPTED_RE = re.compile(
    r"(?is)\b(?:acceptedRoots?|stateRoots?|messageRoots?|rootAccepted|"
    r"verifiedRoots?|trustedRoots?)\s*\[[^\]\n;{}]+\]"
)
_AUTH_CALL_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"(?:verify|verifyProof|verifyMessage|verifyDigest|verifyRoot|"
    r"verifyCommitment|verifyInclusion|proveInclusion|checkProof|"
    r"verifyMerkleProof|verifyMultiproof|multiProofVerify|verifyStorageProof|"
    r"validateContractCall|validateContractCallAndMint|verifyVM|"
    r"isValidProof|isValidSignatureNow|recover|processProof)"
    r"\s*\((?P<args>[^;{}]{0,4200})\)|"
    r"\becrecover\s*\((?P<ecrecover_args>[^;{}]{0,4200})\)"
    r")"
)
_HASH_ASSIGN_RE = re.compile(
    r"\b(?:bytes32\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*"
    r"(?:Digest|Hash|Root|Leaf|Challenge|Transcript|Commitment|Id|ID)?)"
    r"\s*=\s*(?P<expr>(?:keccak256|sha256)\s*\(\s*"
    r"(?:abi\.encode(?:Packed)?|bytes\.concat)\s*\([^;{}]{0,5200}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_HASH_EXPR_RE = re.compile(
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,5200}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_CONSUME_WRITE_RE = re.compile(
    r"(?is)(?P<lvalue>\b(?:consumed|processed|used|seen|executed|"
    r"delivered|claimed|finalized|accepted|settled|completed)[A-Za-z0-9_]*"
    r"\s*(?:\[[^\]\n;{}]+\]\s*)+)\s*=\s*(?:true|1)"
)
_SINK_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:consumed|processed|used|seen|executed|delivered|claimed|"
    r"finalized|accepted|settled|completed)[A-Za-z0-9_]*\s*"
    r"(?:\[[^\]\n;{}]+\]\s*)+\s*=\s*(?:true|1)|"
    r"\b(?:_mint|mint|release|unlock|withdraw|settle|claim|credit|"
    r"executeMessage|executePayload|executeBridgeMessage|execute|deliver|"
    r"dispatch|handle|processMessage|receiveMessage|onMessage|"
    r"onBridgeMessage)\s*\(|"
    r"\b(?:balances?|credits?|escrow|escrowCredit|released|minted)"
    r"[A-Za-z0-9_]*\s*\[[^\]\n;{}]+\]\s*(?:\+=|=)|"
    r"\.\s*(?:safeTransfer|transfer|call|functionCall)\s*(?:\{|\()"
    r")"
)
_SAFE_HELPER_RE = re.compile(
    r"\b(?:BRIDGE_DESTINATION_COMMITMENT_DOMAIN_FIRE37|"
    r"DESTINATION_COMMITMENT_DOMAIN|BRIDGE_SETTLEMENT_DOMAIN|"
    r"SOURCE_COMMITMENT_DOMAIN|DOMAIN_SEPARATOR|domainSeparator|"
    r"_domainSeparatorV4|domainBoundSettlement|domainBoundCommitment|"
    r"domainBoundDestination|hashDestinationSettlement|"
    r"hashDomainBoundSettlement|hashSourceCommitmentDomain|"
    r"bindDestinationCommitment|bindSettlementDomain|"
    r"verifyDestinationSettlement|verifyDomainBoundSettlement)"
    r"[A-Za-z0-9_]*\b",
    re.IGNORECASE,
)
_TRUSTED_CALLER_RE = re.compile(
    r"(?is)\b(?:onlyEndpoint|onlyMailbox|onlyBridge|onlyGateway|"
    r"onlyMessenger|onlyRelayer|onlyRouter|onlyOperator|onlyOwner|"
    r"onlyAdmin|trustedRelayer|authorizedRelayer|knownGateway|"
    r"onlyAuthorizedInbox)\b|"
    r"require\s*\(\s*msg\.sender\s*==\s*\w*(?:Endpoint|Mailbox|Bridge|"
    r"Gateway|Messenger|Relayer|Router|Operator|Admin|Inbox)\b"
)
_CANONICAL_BASE_RE = re.compile(
    r"\b(?:NonblockingLzApp|CCIPReceiver|AxelarExecutable|"
    r"AbstractMessageIdAuth|CrossDomainOwnable|IMessageRecipient|"
    r"ERC7786Receiver|BaseReceiver|CrossChainReceiver)\b",
    re.IGNORECASE,
)
_MOCK_TEST_RE = re.compile(r"\b(?:mock|test|fixture)\b", re.IGNORECASE)

_DOMAIN_GROUP_PATTERNS = (
    (
        "source_commitment",
        re.compile(
            r"\b(?:source|src|origin|remote|from)?\w*"
            r"(?:Commitment|CommitmentHash|MessageHash|Leaf|LeafHash|"
            r"ClaimRoot|ReceiptRoot|TransferId|TransferID|MessageId|"
            r"MessageID|ClaimId|ClaimID|TxId|TxID)\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_chain",
        re.compile(
            r"\b(?:destination|dest|dst|target|local|to)\w*"
            r"(?:ChainId|ChainID|ChainSelector|Selector|Chain|DomainId|"
            r"DomainID|NetworkId|NetworkID|Eid|EID)\b|"
            r"\b(?:block\s*\.\s*chainid|chainid|CHAIN_ID|localEid|"
            r"dstEid)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "receiver_domain",
        re.compile(
            r"\b(?:receiver|recipient|destination|dest|dst|target|local|to)"
            r"\w*(?:Domain|DomainId|DomainID|Receiver|Recipient|App|"
            r"Application|Contract|Address)\b|\b(?:receiver|recipient|"
            r"beneficiary|targetReceiver|destinationReceiver|targetApp|"
            r"receiverDomain|recipientDomain)\b|\baddress\s*\(\s*this\s*\)",
            re.IGNORECASE,
        ),
    ),
    (
        "route_id",
        re.compile(
            r"\b(?:route|routeId|routeID|route_id|routeKey|lane|laneId|"
            r"laneID|channel|channelId|channelID|port|portId|paraId|"
            r"parachain|pathId|pathID)\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "adapter_id",
        re.compile(
            r"\b(?:source|src|origin|remote|destination|dest|dst|target|"
            r"local|trusted)?\w*(?:Adapter|Adaptor|AdapterId|AdapterID|"
            r"AdaptorId|AdaptorID|AdapterAddress|AdaptorAddress|Gateway|"
            r"GatewayAddress|BridgeAdapter|Endpoint|EndpointId|EndpointID)"
            r"\w*\b",
            re.IGNORECASE,
        ),
    ),
)
_GROUP_LABELS = {
    "source_commitment": "source commitment",
    "destination_chain": "destination chain",
    "receiver_domain": "receiver domain",
    "route_id": "route id",
    "adapter_id": "adapter id",
}
_DOMAIN_GROUP_ORDER = tuple(_GROUP_LABELS)
_SECONDARY_GROUPS = {"destination_chain", "receiver_domain", "route_id", "adapter_id"}


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
            pos = max(i, j)
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


def _is_callable(fn: FunctionSlice) -> bool:
    return bool(_CALLABLE_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _domain_groups(text: str) -> set[str]:
    return {name for name, pattern in _DOMAIN_GROUP_PATTERNS if pattern.search(text)}


def _visible_settlement_groups(fn: FunctionSlice) -> set[str]:
    groups = _domain_groups(_context(fn))
    if "source_commitment" in groups and groups & _SECONDARY_GROUPS:
        return groups
    if "route_id" in groups and {"receiver_domain", "adapter_id"} & groups:
        return groups
    return set()


def _hash_assignments_before(body: str, pos: int) -> dict[str, str]:
    assignments: dict[str, str] = {}
    for match in _HASH_ASSIGN_RE.finditer(body[:pos]):
        assignments[match.group("name")] = match.group("expr")
    return assignments


def _last_mapping_key(lvalue: str) -> str:
    parts = _BRACKET_RE.findall(lvalue)
    if not parts:
        return ""
    return parts[-1].strip()


def _key_expr_for_consume(fn: FunctionSlice, consume: re.Match[str]) -> str:
    key = _last_mapping_key(consume.group("lvalue"))
    if not key:
        return ""
    direct_hash = _HASH_EXPR_RE.search(key)
    if direct_hash is not None:
        return direct_hash.group("expr")
    return _hash_assignments_before(fn.body, consume.start()).get(key, key)


def _first_sink(fn: FunctionSlice) -> tuple[re.Match[str] | None, str]:
    sink = _SINK_RE.search(fn.body)
    if sink is None:
        return None, ""
    consume = _CONSUME_WRITE_RE.search(fn.body)
    if consume is not None and consume.start() == sink.start():
        return consume, "consume marker"
    token = sink.group(0)
    if re.search(r"(?is)(?:_mint|mint|safeTransfer|transfer|release|unlock|withdraw|balances?|escrow|credit)", token):
        return sink, "value release"
    return sink, "message execution"


def _auth_exprs_before(fn: FunctionSlice, pos: int) -> list[str]:
    exprs: list[str] = []
    for auth in _AUTH_CALL_RE.finditer(fn.body[:pos]):
        args = auth.group("args") or auth.group("ecrecover_args") or ""
        exprs.append(args)
        exprs.extend(match.group("expr") for match in _HASH_EXPR_RE.finditer(args))

        assignments = _hash_assignments_before(fn.body, auth.start())
        for ident in _IDENT_RE.finditer(args):
            assigned = assignments.get(ident.group(0))
            if assigned:
                exprs.append(assigned)
    return exprs


def _bound_groups(exprs: list[str], visible: set[str]) -> set[str]:
    bound: set[str] = set()
    for expr in exprs:
        if _SAFE_HELPER_RE.search(expr):
            bound.update(visible)
            continue
        bound.update(_domain_groups(expr))
    return bound


def _has_settlement_shape(fn: FunctionSlice) -> bool:
    text = _context(fn)
    if not _is_callable(fn):
        return False
    if _CANONICAL_BASE_RE.search(text) or _TRUSTED_CALLER_RE.search(text):
        return False
    if _MOCK_TEST_RE.search(text):
        return False
    if not (_ENTRY_NAME_RE.search(fn.name) or _BRIDGE_CONTEXT_RE.search(text)):
        return False
    if _BRIDGE_CONTEXT_RE.search(text) is None:
        return False
    if not _visible_settlement_groups(fn):
        return False
    if _PROOF_MATERIAL_RE.search(text) is None:
        return False
    if _ROOT_ACCEPTED_RE.search(fn.body) is None and _AUTH_CALL_RE.search(fn.body) is None:
        return False
    sink, _kind = _first_sink(fn)
    return sink is not None


def _missing_before_sink(fn: FunctionSlice) -> tuple[list[str], re.Match[str] | None, str]:
    visible = _visible_settlement_groups(fn)
    if not visible:
        return [], None, ""

    sink, sink_kind = _first_sink(fn)
    if sink is None:
        return [], None, ""

    exprs = _auth_exprs_before(fn, sink.start())
    if not exprs:
        return [group for group in _DOMAIN_GROUP_ORDER if group in visible], sink, sink_kind

    bound = _bound_groups(exprs, visible)
    missing = [group for group in _DOMAIN_GROUP_ORDER if group in visible and group not in bound]
    if missing:
        return missing, sink, sink_kind
    return [], None, ""


def _finding(
    file_path: str,
    fn: FunctionSlice,
    match: re.Match[str],
    missing: list[str],
    sink_kind: str,
) -> Finding:
    labels = ", ".join(_GROUP_LABELS[item] for item in missing)
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=_line_for(fn, match),
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=fn.name,
        message=(
            "Bridge destination settlement reaches "
            f"{sink_kind} before authenticating destination commitment domain "
            f"fields: {labels}. The function exposes source commitment, "
            "destination chain, receiver domain, route id, or adapter id "
            "material, then consumes, releases, mints, or executes while the "
            "pre-sink proof or replay key omits those fields. NOT_SUBMIT_READY: "
            "detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _has_settlement_shape(fn):
            continue
        missing, match, sink_kind = _missing_before_sink(fn)
        if not missing or match is None:
            continue
        findings.append(_finding(file_path, fn, match, missing, sink_kind))
    return findings


__all__ = [
    "scan",
    "Finding",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
]
