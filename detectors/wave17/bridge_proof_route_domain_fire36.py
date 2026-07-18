"""
bridge-proof-route-domain-fire36

Solidity recall-lift detector for Snowbridge-style BEEFY and adapter route
proof paths that verify a proof digest or consume a replay key while route id, chain id, adapter, verifier address, or destination domain fields are visible but absent from the authenticated preimage or replay namespace.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:a14a00fe6ae82f40
- context_pack_hash: a14a00fe6ae82f4042f8fce336676e437af06060e1f44425bad63447335cb2d7
- source refs:
  - reports/detector_lift_fire35_20260605/post_priorities_all.md
  - reference/patterns.dsl/bridge-proof-domain-bypass-verifier-digest-omits-domain.yaml
  - reference/patterns.dsl/bridge-proof-domain-bypass-umbrella.yaml
  - detectors/wave17/bridge_external_replay_domain_fire34.py
  - detectors/wave17/bridge_beefy_validator_domain_fire35.py
- attack_class: bridge-proof-domain-bypass
- verification_tier: tier-3-synthetic-taxonomy-anchored

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-proof-route-domain-fire36"
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

_ROUTE_CONTEXT_RE = re.compile(
    r"\b(?:bridge|crossChain|crosschain|cross[-_ ]?chain|snowbridge|"
    r"BEEFY|Beefy|beefy|MMR|mmrRoot|gateway|adapter|adaptor|router|"
    r"route|lane|channel|proof|root|commitment|message|payload|packet|"
    r"finality|lightClient|verifier|destination|domain|chain|replay|"
    r"processed|consumed|delivered)\b",
    re.IGNORECASE,
)
_BEEFY_OR_ADAPTER_RE = re.compile(
    r"\b(?:snowbridge|BEEFY|Beefy|beefy|MMR|mmrRoot|"
    r"adapter|adaptor|gateway|routeVerifier|beefyVerifier|lightClient)\b",
    re.IGNORECASE,
)
_ENTRY_NAME_RE = re.compile(
    r"(?i)(submit|verify|process|consume|finalize|prove|relay|receive|"
    r"execute|dispatch|accept|deliver).*(route|proof|message|commitment|"
    r"digest|root|packet|bridge|beefy|adapter|adaptor)?"
)
_PROOF_MATERIAL_RE = re.compile(
    r"\b(?:proof|proofRoot|messageRoot|stateRoot|receiptRoot|root|"
    r"rootHash|mmrRoot|MMRRoot|commitment|commitmentHash|leaf|leafHash|"
    r"payloadHash|payload|messageHash|message|packet|packetHash|nonce|"
    r"sequence|seq|header|digest|transcript|bitFieldHash|signature|sig)\b",
    re.IGNORECASE,
)
_AUTH_CALL_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"(?:verify|verifyProof|verifyRouteProof|verifyMessage|verifyDigest|"
    r"verifyRoot|verifyCommitment|verifyMMRRoot|verifyFinalityProof|"
    r"verifyBeefy[A-Za-z0-9_]*|verifyBEEFY[A-Za-z0-9_]*|"
    r"isValidProof|checkProof|prove|processProof|recover|"
    r"isValidSignatureNow)\s*\((?P<args>[^;{}]{0,3600})\)|"
    r"\becrecover\s*\((?P<ecrecover_args>[^;{}]{0,3600})\)"
    r")"
)
_SINK_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:processed|consumed|used|seen|executed|delivered|claimed|"
    r"finalized|accepted)[A-Za-z0-9_]*\s*(?:\[[^\]\n;{}]+\]\s*)+"
    r"=\s*(?:true|1)|"
    r"\b(?:dispatch|deliver|execute|handle|route|apply|receiveMessage|"
    r"onMessage|onBridgeMessage|processMessage|settle|release|claim|"
    r"mint|unlock|finalize|acceptRouteMessage|deliverRouteMessage)"
    r"\s*\(|"
    r"\bI[A-Za-z0-9_]*(?:Gateway|Bridge|Adapter|Adaptor|Endpoint|Receiver|"
    r"Application|App|Mailbox|Messenger|Router)\s*\([^;{}]*\)\s*\."
    r"(?:dispatch|deliver|execute|handle|route|apply|receiveMessage|"
    r"onBridgeMessage|processMessage|acceptRouteMessage|deliverRouteMessage)"
    r"\s*\(|"
    r"\.\s*(?:call|delegatecall|functionCall|safeTransfer|transfer)"
    r"\s*(?:\{|\()"
    r")"
)
_CONSUME_WRITE_RE = re.compile(
    r"(?is)(?P<lvalue>\b(?:consumed|processed|used|seen|executed|"
    r"delivered|claimed|finalized|accepted)[A-Za-z0-9_]*\s*"
    r"(?:\[[^\]\n;{}]+\]\s*)+)\s*=\s*(?:true|1)"
)
_BRACKET_RE = re.compile(r"\[([^\]\n;{}]+)\]")
_HASH_ASSIGN_RE = re.compile(
    r"\b(?:bytes32\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*"
    r"(?:Digest|Hash|Root|Leaf|Challenge|Transcript|Id|ID|Key)?)\s*=\s*"
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,4200}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_HASH_EXPR_RE = re.compile(
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,4200}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_SAFE_HELPER_RE = re.compile(
    r"\b(?:BRIDGE_PROOF_ROUTE_DOMAIN_FIRE36|BRIDGE_ROUTE_DOMAIN|"
    r"ROUTE_DOMAIN_SEPARATOR|ROUTE_REPLAY_DOMAIN|BEEFY_ROUTE_DOMAIN|"
    r"SNOWBRIDGE_ROUTE_DOMAIN|DOMAIN_SEPARATOR|domainSeparator|"
    r"_domainSeparatorV4|domainBoundRouteDigest|domainBoundRouteProof|"
    r"hashRouteDomain|hashDomainBoundRouteProof|bindRouteDomain|"
    r"bindBridgeRouteDomain|verifyDomainBoundRoute[A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_TRUSTED_CALLER_RE = re.compile(
    r"(?is)\b(?:onlyEndpoint|onlyMailbox|onlyBridge|onlyGateway|"
    r"onlyMessenger|onlyRelayer|onlyRouter|onlyOperator|onlyOwner|"
    r"onlyAdmin|trustedRelayer|authorizedRelayer|knownGateway)\b|"
    r"require\s*\(\s*msg\.sender\s*==\s*\w*(?:Endpoint|Mailbox|Bridge|"
    r"Gateway|Messenger|Relayer|Router|Operator|Admin)\b"
)
_CANONICAL_BASE_RE = re.compile(
    r"\b(?:NonblockingLzApp|CCIPReceiver|AxelarExecutable|"
    r"AbstractMessageIdAuth|CrossDomainOwnable|IMessageRecipient)\b",
    re.IGNORECASE,
)
_MOCK_TEST_RE = re.compile(r"\b(?:mock|test|fixture)\b", re.IGNORECASE)

_DOMAIN_GROUP_PATTERNS = (
    (
        "route_id",
        re.compile(
            r"\b(?:route|routeId|routeID|route_id|routeKey|routeNonce|"
            r"messageRoute|bridgeRoute|lane|laneId|laneID|channel|"
            r"channelId|channelID|port|portId|paraId|parachain)\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "source_chain",
        re.compile(
            r"\b(?:source|src|origin|remote|from|relay)\w*"
            r"(?:ChainId|ChainID|Chain|Domain|DomainId|DomainID|"
            r"NetworkId|NetworkID|Eid|EID|Selector)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_chain",
        re.compile(
            r"\b(?:destination|dest|dst|target|local|to)\w*"
            r"(?:ChainId|ChainID|Chain|DomainId|DomainID|NetworkId|"
            r"NetworkID|Eid|EID|Selector)\b|\b(?:block\s*\.\s*chainid|"
            r"chainid|CHAIN_ID|localEid|dstEid)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_domain",
        re.compile(
            r"\b(?:destination|dest|dst|target|local|to)\w*"
            r"(?:Domain|DomainId|DomainID|RouteDomain|ProofDomain)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "adapter_address",
        re.compile(
            r"\b(?:source|src|origin|remote|destination|dest|dst|target|"
            r"local|trusted)?\w*(?:Adapter|Adaptor|AdapterAddress|"
            r"AdaptorAddress|Gateway|GatewayAddress|BridgeAdapter)\w*\b|"
            r"\baddress\s*\(\s*this\s*\)",
            re.IGNORECASE,
        ),
    ),
    (
        "verifier_address",
        re.compile(
            r"\b(?:route|proof|beefy|BEEFY|lightClient|bridge|message|"
            r"trusted|external)?\w*(?:Verifier|VerifierAddress|"
            r"LightClient|LightClientAddress|BeefyClient|BeefyVerifier)"
            r"\w*\b",
            re.IGNORECASE,
        ),
    ),
)
_GROUP_LABELS = {
    "route_id": "route id",
    "source_chain": "source chain id",
    "destination_chain": "destination chain id",
    "destination_domain": "destination domain",
    "adapter_address": "adapter address",
    "verifier_address": "verifier address",
}
_SECONDARY_ROUTE_GROUPS = {
    "source_chain",
    "destination_chain",
    "destination_domain",
    "adapter_address",
    "verifier_address",
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


def _domain_groups(text: str) -> set[str]:
    return {name for name, pattern in _DOMAIN_GROUP_PATTERNS if pattern.search(text)}


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


def _is_callable(fn: FunctionSlice) -> bool:
    return bool(_CALLABLE_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _visible_route_domain_groups(fn: FunctionSlice) -> set[str]:
    visible = _domain_groups(_context(fn))
    if "route_id" not in visible:
        return set()
    if len(visible & _SECONDARY_ROUTE_GROUPS) < 2:
        return set()
    return visible


def _has_route_proof_shape(fn: FunctionSlice) -> bool:
    text = _context(fn)
    if not _is_callable(fn):
        return False
    if _CANONICAL_BASE_RE.search(text) or _TRUSTED_CALLER_RE.search(text):
        return False
    if _MOCK_TEST_RE.search(text):
        return False
    if not (_ENTRY_NAME_RE.search(fn.name) or _ROUTE_CONTEXT_RE.search(text)):
        return False
    if _ROUTE_CONTEXT_RE.search(text) is None or _BEEFY_OR_ADAPTER_RE.search(text) is None:
        return False
    if not _visible_route_domain_groups(fn):
        return False
    if _PROOF_MATERIAL_RE.search(text) is None:
        return False
    if _AUTH_CALL_RE.search(fn.body) is None:
        return False
    if _SINK_RE.search(fn.body) is None:
        return False
    return _HASH_EXPR_RE.search(fn.body) is not None


def _authenticated_digest_exprs(fn: FunctionSlice, auth: re.Match[str]) -> list[str]:
    args = auth.group("args") or auth.group("ecrecover_args") or ""
    out: list[str] = []
    out.extend(match.group("expr") for match in _HASH_EXPR_RE.finditer(args))

    assignments = _hash_assignments_before(fn.body, auth.start())
    for ident_match in _IDENT_RE.finditer(args):
        expr = assignments.get(ident_match.group(0))
        if expr:
            out.append(expr)
    return out


def _sink_after_auth(fn: FunctionSlice, auth: re.Match[str]) -> bool:
    return _SINK_RE.search(fn.body[auth.end():]) is not None


def _missing_route_groups(visible: set[str], expr: str) -> list[str]:
    if _SAFE_HELPER_RE.search(expr):
        return []
    if _PROOF_MATERIAL_RE.search(expr) is None:
        return []
    bound = _domain_groups(expr)
    missing = [group for group in _GROUP_LABELS if group in visible and group not in bound]
    if not missing:
        return []
    return missing


def _unsafe_route_proof(fn: FunctionSlice) -> tuple[list[str], re.Match[str] | None, str]:
    visible = _visible_route_domain_groups(fn)
    if not visible:
        return [], None, ""

    for auth in _AUTH_CALL_RE.finditer(fn.body):
        if not _sink_after_auth(fn, auth):
            continue
        for expr in _authenticated_digest_exprs(fn, auth):
            missing = _missing_route_groups(visible, expr)
            if missing:
                return missing, auth, "authenticated digest"

        for consume in _CONSUME_WRITE_RE.finditer(fn.body):
            if consume.start() <= auth.end():
                continue
            key_expr = _key_expr_for_consume(fn, consume)
            missing = _missing_route_groups(visible, key_expr)
            if missing:
                return missing, consume, "replay key"
    return [], None, ""


def _finding(
    file_path: str,
    fn: FunctionSlice,
    match: re.Match[str],
    missing: list[str],
    key_kind: str,
) -> Finding:
    labels = ", ".join(_GROUP_LABELS[item] for item in missing)
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=_line_for(fn, match),
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=fn.name,
        message=(
            f"Bridge route proof {key_kind} omits route replay domain fields: "
            f"{labels}. The function verifies a BEEFY, MMR, or adapter route "
            "proof, then consumes or dispatches under visible route id, chain id, "
            "destination domain, adapter, or verifier address fields that are "
            "not bound into the proof digest or replay key. NOT_SUBMIT_READY: "
            "detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _has_route_proof_shape(fn):
            continue
        missing, match, key_kind = _unsafe_route_proof(fn)
        if not missing or match is None:
            continue
        findings.append(_finding(file_path, fn, match, missing, key_kind))
    return findings


__all__ = [
    "scan",
    "Finding",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
]
