"""
go-bridge-route-domain-fire37.py

Fire37 Go lift for bridge-proof-domain-bypass route binding.

Flags Go bridge, light-client, packet, and settlement verification handlers
where route id, chain id, client id, validator set id, receiver domain, or
source commitment context is visible before a root, message, packet, or
settlement state is accepted, but those coordinates are absent from the proof
leaf, verifier call, signed commitment, or decoded proof-key equality checks.

Rule 37 provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- attack_class: bridge-proof-domain-bypass
- source refs:
  - reports/detector_lift_fire36_20260605/post_priorities_go.md
  - reference/patterns.dsl/bridge-proof-domain-bypass-umbrella.yaml
  - detectors/rust_wave1/bridge_lightclient_route_binding_fire36.py
  - detectors/go_wave1/go-oracle-threshold-staleness-fire36.py

Detector hits are source-review candidates only and are NOT_SUBMIT_READY.
R40 and R80 proof still require a real in-scope PoC before any finding can
cite the result as load-bearing evidence.
"""

from __future__ import annotations

import re


DETECTOR_ID = "go_wave1.go-bridge-route-domain-fire37"
ATTACK_CLASS = "bridge-proof-domain-bypass"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"

_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_BRIDGE_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|cross.?chain|gateway|portal|relayer|relay|route|router|lane|"
    r"channel|packet|message|settlement|settle|withdrawal|claim|proof|"
    r"verifier|verify|light.?client|client.?state|consensus.?state|"
    r"state.?root|storage.?root|message.?root|packet.?root|commitment|"
    r"validator.?set|vset|beefy|grandpa|ibc|ismp"
    r")\b"
)

_ENTRY_NAME_RE = re.compile(
    r"(?i)("
    r"(submit|update|import|accept|verify|validate|process|finalize|"
    r"settle|relay|prove|consume|store|record|handle)"
    r".*(route|client|light|proof|root|commitment|validator|packet|"
    r"message|settlement|state)"
    r"|"
    r"(route|client|light|proof|root|commitment|validator|packet|"
    r"message|settlement|state)"
    r".*(submit|update|import|accept|verify|validate|process|finalize|"
    r"settle|relay|prove|consume|store|record|handle)"
    r")"
)

_PROOF_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"proof|proofKey|proof_key|proofPath|proof_path|storageKey|stateKey|"
    r"routeKey|membershipKey|stateRoot|storageRoot|headerRoot|"
    r"messageRoot|packetRoot|receiptRoot|rootHash|messageHash|packetHash|"
    r"commitment|sourceCommitment|validatorSet|validatorSetID|leaf|"
    r"digest|merkle|nodes|header|packet|payload"
    r")\b"
)

_VERIFY_CALL_RE = re.compile(
    r"(?i)\b("
    r"Verify(?:Bridge|Client|LightClient|State|Storage|Header|Root|"
    r"Message|Packet|Commitment|Membership|Merkle|Proof|ValidatorSet|"
    r"Finality)?[A-Za-z0-9_]*"
    r"|Validate(?:Bridge|Client|State|Root|Message|Packet|Commitment|"
    r"Membership|Merkle|Proof|ValidatorSet)?[A-Za-z0-9_]*"
    r"|Check(?:Membership|Proof|MerkleProof|Root|Packet|Message)[A-Za-z0-9_]*"
    r"|ConsumeProof|AuthenticateProof|VerifyMembership"
    r")\s*\("
)

_HASH_OR_BUILD_CALL_RE = re.compile(
    r"(?i)\b("
    r"sha256\.Sum256|sha512\.Sum512|tmhash\.Sum|crypto\.Keccak256Hash|"
    r"Keccak256Hash|blake2b\.Sum256|blake2s\.Sum256|Hash[A-Za-z0-9_]*|"
    r"Build[A-Za-z0-9_]*(?:Key|Leaf|Digest|Hash|Commitment)|"
    r"Digest[A-Za-z0-9_]*|MessageLeaf|PacketLeaf|ProofLeaf|RootLeaf|"
    r"CommitmentLeaf"
    r")\s*\("
)

_ASSIGN_RE = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*(?P<expr>[^;\n]+)"
)

_ACCEPT_ASSIGN_RE = re.compile(
    r"(?is)\b("
    r"(?:k|s|keeper|state|store|cache|db)\."
    r"[A-Za-z0-9_\.]*(?:Root|Roots|Message|Messages|Packet|Packets|"
    r"Settlement|Settlements|Commitment|Commitments|ValidatorSet|"
    r"ValidatorSets|ClientState|ClientStates|ConsensusState|"
    r"ConsensusStates|Accepted|Trusted|Verified|Processed|Consumed|"
    r"Finalized|Settled)[A-Za-z0-9_\.]*(?:\s*\[[^\]\n]+\])?"
    r"|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:Roots|Messages|Packets|Settlements|"
    r"Commitments|ValidatorSets|ClientStates|ConsensusStates)"
    r"\s*\[[^\]\n]+\]"
    r")\s*(?:=|:=)"
)

_ACCEPT_CALL_RE = re.compile(
    r"(?is)\b("
    r"[A-Za-z0-9_\.]*(?:root|roots|message|messages|packet|packets|"
    r"settlement|settlements|commitment|commitments|validator|client|"
    r"consensus)[A-Za-z0-9_\.]*\."
    r"(?:Set|Save|Store|Put|Insert|Update|Record|Mark)[A-Za-z0-9_]*"
    r"|"
    r"(?:Set|Save|Store|Put|Insert|Update|Accept|Record|Finalize|"
    r"MarkAccepted|MarkProcessed)[A-Za-z0-9_]*(?:Root|Message|Packet|"
    r"Settlement|Commitment|ValidatorSet|ClientState|ConsensusState)"
    r")\s*\("
)

_SAFE_BINDING_HELPER_RE = re.compile(
    r"(?i)\b("
    r"domainSeparated|DomainSeparated|domain_separated|DOMAIN_SEPARATOR|"
    r"Bind[A-Za-z0-9_]*(?:Route|Domain|Chain|Client|Validator|Receiver|"
    r"Commitment)|"
    r"Build[A-Za-z0-9_]*(?:Route|Domain|Chain|Client|Validator|Receiver|"
    r"Commitment)[A-Za-z0-9_]*(?:Key|Leaf|Digest|Hash)|"
    r"Validate[A-Za-z0-9_]*(?:Route|Domain|Chain|Client|Validator|"
    r"Receiver|Commitment)[A-Za-z0-9_]*(?:Binding|Match|Scope|Scoped)?|"
    r"Ensure[A-Za-z0-9_]*(?:Route|Domain|Chain|Client|Validator|"
    r"Receiver|Commitment)[A-Za-z0-9_]*(?:Binding|Match|Scope|Scoped)?|"
    r"Check[A-Za-z0-9_]*(?:Route|Domain|Chain|Client|Validator|"
    r"Receiver|Commitment)[A-Za-z0-9_]*(?:Binding|Match|Scope|Scoped)?|"
    r"ProofKeyMatchesRoute|KeyMatchesRoute|WrongDomain|InvalidDomain|"
    r"WrongClient|InvalidClient|WrongRoute|InvalidRoute|WrongChain|"
    r"InvalidChain|WrongValidatorSet|InvalidValidatorSet|WrongReceiver|"
    r"InvalidReceiver|WrongCommitment|InvalidCommitment"
    r")\b"
)

_COMPARE_RE = re.compile(
    r"(?:==|!=|\.Equal\s*\(|\.Equals\s*\(|bytes\.Equal\s*\(|BytesEqual\s*\()"
)
_DECODED_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"decoded|parsed|proofKey|proof_key|routeKey|stateKey|storageKey|"
    r"packetKey|messageKey|commitmentKey|membershipKey|proof\.|packet\."
    r"|message\.|header\.|claim\.|attestation\."
    r")"
)

_DOMAIN_FIELDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "chain_id",
        re.compile(
            r"(?i)\b("
            r"chainID|chainId|chain_id|sourceChain|sourceChainID|srcChain|"
            r"srcChainID|originChain|originChainID|remoteChain|remoteChainID|"
            r"destinationChain|destinationChainID|destChain|dstChain|"
            r"dstChainID|targetChain|localChain|networkID|networkId|"
            r"genesisHash|forkID"
            r")\b"
        ),
    ),
    (
        "client_id",
        re.compile(
            r"(?i)\b("
            r"clientID|clientId|client_id|lightClientID|lightClientId|"
            r"ibcClientID|ibcClientId|ismpClientID|ismpClientId|"
            r"consensusClientID|clientStateID|clientKey"
            r")\b"
        ),
    ),
    (
        "route_id",
        re.compile(
            r"(?i)\b("
            r"routeID|routeId|route_id|route|laneID|laneId|lane_id|lane|"
            r"channelID|channelId|channel_id|portID|portId|port_id|"
            r"pathID|pathId|counterpartyChannel|gatewayID|gatewayId|"
            r"bridgeID|bridgeId"
            r")\b"
        ),
    ),
    (
        "validator_set_id",
        re.compile(
            r"(?i)\b("
            r"validatorSetID|validatorSetId|validator_set_id|"
            r"validatorSetHash|validatorSetRoot|vsetID|vsetId|"
            r"authoritySetID|authoritySetId|authoritySetHash|committeeID|"
            r"committeeId|signerSetID|signerSetId"
            r")\b"
        ),
    ),
    (
        "receiver_domain",
        re.compile(
            r"(?i)\b("
            r"receiverDomain|recipientDomain|receiver_domain|"
            r"destinationDomain|destDomain|dstDomain|targetDomain|"
            r"localDomain|receiverChain|recipientChain|receiverNamespace|"
            r"recipientNamespace|toDomain|toChain"
            r")\b"
        ),
    ),
    (
        "source_commitment",
        re.compile(
            r"(?i)\b("
            r"sourceCommitment|source_commitment|sourceRoot|sourceStateRoot|"
            r"sourceMessageRoot|sourcePacketRoot|sourcePacketCommitment|"
            r"sourceReceiptRoot|sourceCommitmentRoot|originRoot|remoteRoot|"
            r"remoteCommitment|counterpartyCommitment"
            r")\b"
        ),
    ),
)

_LOAD_BEARING_FIELDS = {
    "chain_id",
    "client_id",
    "route_id",
    "validator_set_id",
    "receiver_domain",
    "source_commitment",
}


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    return _COMMENT_RE.sub(_blank, src)


def _strip_comments_and_strings(src: str) -> str:
    return _STRING_RE.sub(_blank, _strip_comments(src))


def _domain_groups(text: str) -> set[str]:
    return {
        name
        for name, pattern in _DOMAIN_FIELDS
        if pattern.search(text)
    } & _LOAD_BEARING_FIELDS


def _extract_call(text: str, start: int) -> str:
    open_idx = text.find("(", start)
    if open_idx < 0:
        return text[start : start + 240]
    depth = 0
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start : idx + 1]
    return text[start : start + 240]


def _assignments(body_text: str) -> dict[str, str]:
    return {
        match.group("name"): match.group("expr")
        for match in _ASSIGN_RE.finditer(body_text)
    }


def _expand_expr(expr: str, assignments: dict[str, str]) -> list[str]:
    parts = [expr]
    seen = {expr}
    changed = True
    while changed and len(parts) < 80:
        changed = False
        for item in list(parts):
            for name, assigned in assignments.items():
                if assigned in seen:
                    continue
                if re.search(rf"\b{re.escape(name)}\b", item):
                    parts.append(assigned)
                    seen.add(assigned)
                    changed = True
    return parts


def _authenticated_input_text(prefix: str) -> str:
    assignments = _assignments(prefix)
    inputs: list[str] = []

    for match in _VERIFY_CALL_RE.finditer(prefix):
        call = _extract_call(prefix, match.start())
        inputs.extend(_expand_expr(call, assignments))
    for match in _HASH_OR_BUILD_CALL_RE.finditer(prefix):
        call = _extract_call(prefix, match.start())
        inputs.extend(_expand_expr(call, assignments))
    for expr in assignments.values():
        if _VERIFY_CALL_RE.search(expr) or _HASH_OR_BUILD_CALL_RE.search(expr):
            inputs.extend(_expand_expr(expr, assignments))

    return "\n".join(inputs)


def _comparison_bound_fields(prefix: str) -> set[str]:
    bound: set[str] = set()
    for line in prefix.splitlines():
        if not _COMPARE_RE.search(line):
            continue
        if not _DECODED_CONTEXT_RE.search(line):
            continue
        bound.update(_domain_groups(line))
    return bound


def _first_acceptance_site(body_text: str) -> re.Match[str] | None:
    candidates: list[re.Match[str]] = []
    candidates.extend(_ACCEPT_ASSIGN_RE.finditer(body_text))
    candidates.extend(_ACCEPT_CALL_RE.finditer(body_text))
    if not candidates:
        return None
    return min(candidates, key=lambda match: match.start())


def _candidate_context(name: str, fn_text: str) -> bool:
    return bool(_ENTRY_NAME_RE.search(name) or _BRIDGE_CONTEXT_RE.search(fn_text))


def _missing_route_fields(signature_text: str, prefix: str) -> set[str]:
    visible = _domain_groups(f"{signature_text}\n{prefix}")
    if not visible:
        return set()

    auth_inputs = _authenticated_input_text(prefix)
    if not auth_inputs.strip():
        return set()

    bound = _domain_groups(auth_inputs)
    bound.update(_comparison_bound_fields(prefix))
    return visible - bound


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue

        body = engine.fn_body(fn)
        if body is None:
            continue

        raw_fn_text = engine.text(fn)
        fn_text = _strip_comments(raw_fn_text)
        fn_text_clean = _strip_comments_and_strings(raw_fn_text)
        body_text = _strip_comments_and_strings(engine.text(body))

        if not _candidate_context(name, fn_text_clean):
            continue
        if not _PROOF_MATERIAL_RE.search(fn_text_clean):
            continue

        acceptance = _first_acceptance_site(body_text)
        if acceptance is None:
            continue

        prefix = body_text[: acceptance.start()]
        if not _VERIFY_CALL_RE.search(prefix):
            continue
        if not (_HASH_OR_BUILD_CALL_RE.search(prefix) or _PROOF_MATERIAL_RE.search(prefix)):
            continue
        if _SAFE_BINDING_HELPER_RE.search(prefix):
            continue

        signature_text = fn_text.split("{", 1)[0]
        missing = _missing_route_fields(signature_text, prefix)
        if not missing:
            continue

        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "attack_class": ATTACK_CLASS,
                "verification_tier": VERIFICATION_TIER,
                "severity": "high",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": raw_fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` accepts bridge proof state before binding "
                    f"{', '.join(sorted(missing))} into the proof leaf, "
                    f"verifier input, or decoded proof-key equality checks. "
                    f"Bind route id, chain id, client id, validator set id, "
                    f"receiver domain, and source commitment before accepting "
                    f"roots, messages, packets, or settlements. "
                    f"NOT_SUBMIT_READY source-review hit only. "
                    f"(class: {ATTACK_CLASS})"
                ),
            }
        )

    return hits
