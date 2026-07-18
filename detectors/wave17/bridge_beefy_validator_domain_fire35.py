"""
bridge-beefy-validator-domain-fire35.

Solidity recall-lift detector for BEEFY, light-client, or validator-set proof
verification paths that build a signed or hashed transcript from proof material
while accepting validator-set id, commitment root, source chain, destination
domain, or adapter address outside that transcript.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:5a29d91bbce92794
- context_pack_hash: 5a29d91bbce92794762a8ed09f2250a9242a49986ce3809863c10a012720379d
- source refs:
  - reports/detector_lift_fire34_20260605/post_priorities_all.md
  - reference/patterns.dsl/bridge-proof-domain-bypass-umbrella.yaml
  - reference/patterns.dsl/bridge-proof-domain-bypass-verifier-digest-omits-domain.yaml
  - reference/patterns.dsl/bridge-fiat-shamir-transcript-omits-validator-set-domain.yaml
  - detectors/wave17/bridge_beefy_commitment_domain_fire30.py
  - detectors/wave17/bridge_external_replay_domain_fire34.py
- attack_class: bridge-proof-domain-bypass
- verification_tier: tier-3-synthetic-taxonomy-anchored

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-beefy-validator-domain-fire35"
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

_BEEFY_VALIDATOR_CONTEXT_RE = re.compile(
    r"\b(?:BEEFY|Beefy|beefy|MMR|MMRRoot|lightClient|light[-_ ]?client|"
    r"validatorSet|ValidatorSet|validator[-_ ]?set|authoritySet|"
    r"AuthoritySet|finality|commitmentRoot|commitmentHash|bitFieldHash|"
    r"Fiat.?Shamir|transcript|signedTranscript|proofTranscript)\b",
    re.IGNORECASE,
)
_ENTRY_NAME_RE = re.compile(
    r"(?i)(submit|verify|process|accept|finalize|prove|relay|import|"
    r"consume).*(beefy|validator|authority|finality|commitment|root|"
    r"proof|transcript|digest|header|light.?client)?"
)
_TRANSCRIPT_MATERIAL_RE = re.compile(
    r"\b(?:proof|proofRoot|root|rootHash|mmrRoot|MMRRoot|commitment|"
    r"commitmentHash|commitmentRoot|payload|payloadHash|message|"
    r"messageHash|header|headerHash|leaf|leafHash|digest|transcript|"
    r"challenge|ballot|signature|sig|bitField|bitfield|bitFieldHash|"
    r"validatorSetRoot|authoritySetRoot)\b",
    re.IGNORECASE,
)
_HASH_ASSIGN_RE = re.compile(
    r"\b(?:bytes32\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*"
    r"(?:Digest|Hash|Root|Leaf|Challenge|Transcript|Commitment|Proof)?)"
    r"\s*=\s*"
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)?\s*\(?[^;{}]{0,4200}\)\s*\)?)",
    re.IGNORECASE | re.DOTALL,
)
_HASH_EXPR_RE = re.compile(
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)?\s*\(?[^;{}]{0,4200}\)\s*\)?)",
    re.IGNORECASE | re.DOTALL,
)
_AUTH_CALL_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"(?:verify(?:BEEFY|Beefy|Validator|ValidatorSet|Authority|"
    r"AuthoritySet|Finality|LightClient|MMR|Commitment|Proof|Digest)"
    r"[A-Za-z0-9_]*|verify[A-Za-z0-9_]*(?:Proof|Digest|Commitment|"
    r"Transcript)|isValidSignatureNow|recover)\s*\("
    r"(?P<args>[^;{}]{0,3600})\)|"
    r"\becrecover\s*\((?P<ecrecover_args>[^;{}]{0,3600})\)"
    r")"
)
_SINK_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:accepted|verified|processed|consumed|used|finalized)"
    r"[A-Za-z0-9_]*\s*(?:\[[^\]\n;{}]+\]\s*)+=\s*(?:true|1)|"
    r"\b(?:latest|trusted|accepted|verified|finalized)[A-Za-z0-9_]*"
    r"(?:Root|Commitment|Header|Digest)\s*=\s*|"
    r"\b(?:accept|import|submit|finalize|process|update)[A-Za-z0-9_]*"
    r"(?:Root|Commitment|Header|Digest)\s*\(|"
    r"\bI[A-Za-z0-9_]*(?:Adapter|Adaptor|Gateway|LightClient|Bridge)"
    r"\s*\([^;{}]*\)\s*\."
    r"(?:accept|import|submit|finalize|process|update)[A-Za-z0-9_]*"
    r"\s*\(|"
    r"emit\s+[A-Za-z0-9_]*(?:Root|Commitment|Validator|Finality)"
    r"[A-Za-z0-9_]*\s*\("
    r")"
)
_SAFE_HELPER_RE = re.compile(
    r"\b(?:BEEFY_VALIDATOR_DOMAIN_FIRE35|BEEFY_VALIDATOR_DOMAIN|"
    r"BEEFY_PROOF_DOMAIN|BEEFY_TRANSCRIPT_DOMAIN|"
    r"FIAT_SHAMIR_DOMAIN_ID|DOMAIN_ID|DOMAIN_SEPARATOR|"
    r"domainSeparator|_domainSeparatorV4|domainBoundBeefyValidatorDigest|"
    r"domainBoundValidatorTranscript|domainBoundBeefyTranscript|"
    r"bindBeefyValidatorDomain|bindValidatorSetDomain|"
    r"hashBeefyValidatorDomain|hashDomainBoundValidatorProof|"
    r"verifyDomainBound[A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_MOCK_TEST_RE = re.compile(r"\b(?:mock|test|fixture)\b", re.IGNORECASE)

_DOMAIN_GROUP_PATTERNS = (
    (
        "validator_set_id",
        re.compile(
            r"\b(?:validatorSetID|validatorSetId|validator_set_id|"
            r"authoritySetID|authoritySetId|authority_set_id|vset\.id|"
            r"currentValidatorSet\.id|nextValidatorSet\.id)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "validator_set_root",
        re.compile(
            r"\b(?:validatorSetRoot|validator_set_root|authoritySetRoot|"
            r"authority_set_root|vset\.root|currentValidatorSet\.root|"
            r"nextValidatorSet\.root)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "validator_set_length",
        re.compile(
            r"\b(?:validatorSetLength|validatorSetLen|validator_set_len|"
            r"authoritySetLength|authoritySetLen|authority_set_len|"
            r"vset\.length|currentValidatorSet\.length|"
            r"nextValidatorSet\.length)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "commitment_root",
        re.compile(
            r"\b(?:commitmentRoot|commitment_root|acceptedCommitmentRoot|"
            r"newCommitmentRoot|mmrRoot|MMRRoot|newMMRRoot|beefyRoot|"
            r"latestBeefyRoot|finalityRoot)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "source_chain",
        re.compile(
            r"\b(?:source|src|origin|remote|relay|from)\w*"
            r"(?:ChainId|ChainID|Chain|Domain|DomainId|DomainID|"
            r"NetworkId|NetworkID|Eid|EID)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_domain",
        re.compile(
            r"\b(?:destination|dest|dst|target|local|to)\w*"
            r"(?:ChainId|ChainID|Chain|Domain|DomainId|DomainID|"
            r"NetworkId|NetworkID|Eid|EID)\b|"
            r"\b(?:block\s*\.\s*chainid|chainid|CHAIN_ID)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "adapter_address",
        re.compile(
            r"\b(?:source|src|origin|remote|destination|dest|dst|target|"
            r"local|trusted)?\w*(?:Adapter|Adaptor|AdapterAddress|"
            r"AdaptorAddress|Gateway|GatewayAddress)\w*\b|"
            r"\baddress\s*\(\s*this\s*\)",
            re.IGNORECASE,
        ),
    ),
)
_GROUP_LABELS = {
    "validator_set_id": "validator-set id",
    "validator_set_root": "validator-set root",
    "validator_set_length": "validator-set length",
    "commitment_root": "commitment root",
    "source_chain": "source chain",
    "destination_domain": "destination domain",
    "adapter_address": "adapter address",
}
_CORE_GROUPS = {
    "validator_set_id",
    "validator_set_root",
    "validator_set_length",
    "commitment_root",
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


def _is_callable(fn: FunctionSlice) -> bool:
    return bool(_CALLABLE_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _visible_domain_groups(fn: FunctionSlice) -> set[str]:
    visible = _domain_groups(_context(fn))
    if len(visible) < 3:
        return set()
    if not (visible & _CORE_GROUPS):
        return set()
    return visible


def _has_beefy_validator_auth_shape(fn: FunctionSlice) -> bool:
    text = _context(fn)
    if not _is_callable(fn):
        return False
    if _MOCK_TEST_RE.search(text):
        return False
    if not (_ENTRY_NAME_RE.search(fn.name) or _BEEFY_VALIDATOR_CONTEXT_RE.search(text)):
        return False
    if _BEEFY_VALIDATOR_CONTEXT_RE.search(text) is None:
        return False
    if not _visible_domain_groups(fn):
        return False
    if _TRANSCRIPT_MATERIAL_RE.search(text) is None:
        return False
    if _AUTH_CALL_RE.search(fn.body) is None:
        return False
    if _SINK_RE.search(fn.body) is None:
        return False
    return _HASH_EXPR_RE.search(fn.body) is not None


def _authenticated_transcript_exprs(fn: FunctionSlice, auth: re.Match[str]) -> list[str]:
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


def _unsafe_authentication(fn: FunctionSlice) -> tuple[list[str], re.Match[str] | None]:
    visible = _visible_domain_groups(fn)
    if not visible:
        return [], None

    for auth in _AUTH_CALL_RE.finditer(fn.body):
        if not _sink_after_auth(fn, auth):
            continue
        for expr in _authenticated_transcript_exprs(fn, auth):
            if _SAFE_HELPER_RE.search(expr):
                continue
            if _TRANSCRIPT_MATERIAL_RE.search(expr) is None:
                continue
            bound = _domain_groups(expr)
            missing = sorted(visible - bound)
            if len(missing) < 2:
                continue
            if not (set(missing) & _CORE_GROUPS):
                continue
            return missing, auth
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
            "BEEFY validator proof transcript omits replay domain fields: "
            f"{labels}. The function verifies a signed or hashed validator "
            "proof transcript, then accepts a commitment/root or dispatches "
            "under visible validator-set, chain, destination, or adapter "
            "fields that are not all bound into the authenticated transcript. "
            "NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _has_beefy_validator_auth_shape(fn):
            continue
        missing, match = _unsafe_authentication(fn)
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
