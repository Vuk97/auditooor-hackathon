"""
go-signature-domain-replay-fire37.py

Fire37 Go lift for signature-replay-cross-domain in custom signature,
threshold, aggregate, and transcript verification paths.

This detector flags Go functions that:
- verify ed25519, secp256k1, ECDSA, BLS-style aggregate, or FROST-style
  signature-share material,
- authenticate locally built message bytes, digest bytes, or transcript
  challenge bytes,
- apply a state effect after verification, and
- leave visible replay-scope fields outside the authenticated bytes.

Replay-scope fields are chain id, domain separator, session id, signer role,
participant set, and purpose or action binding.

Rule 37 provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- attack_class: signature-replay-cross-domain
- source refs:
  - reports/detector_lift_fire36_20260605/post_priorities_go.md
  - reference/patterns.dsl/signature-replay-cross-domain.yaml
    requested by brief but absent in this worktree
  - reference/patterns.dsl/signature-replay-missing-domain.yaml
  - detectors/rust_wave1/signature_domain_replay_fire36.py
  - reference/patterns.dsl/go.spark.coop_exit.key_tweak_resumability.yaml

Detector hits are source-review candidates only and are NOT_SUBMIT_READY.
R40 and R80 proof still require a real in-scope PoC before a finding can
cite detector output as load-bearing evidence.
"""

from __future__ import annotations

import re


DETECTOR_ID = "go_wave1.go-signature-domain-replay-fire37"
ATTACK_CLASS = "signature-replay-cross-domain"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"

_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_CRYPTO_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"signature|signed|signer|verify|verification|auth|authorization|"
    r"ed25519|secp256k1|secp256r1|ecdsa|schnorr|bls|frost|threshold|"
    r"aggregate|signatureShare|signature_share|transcript|challenge|"
    r"digest|signBytes|sign_bytes|permit|intent|session"
    r")\b"
)

_ENTRY_FN_RE = re.compile(
    r"(?i)("
    r"(verify|validate|execute|consume|claim|redeem|release|settle|permit|"
    r"authorize|submit|process|complete|finalize).*"
    r"(signature|signed|permit|authorization|intent|digest|transcript|"
    r"session|frost|bls|ed25519|secp)"
    r"|"
    r"(signature|signed|permit|authorization|intent|digest|transcript|"
    r"session|frost|bls|ed25519|secp).*"
    r"(verify|validate|execute|consume|claim|redeem|release|settle|permit|"
    r"authorize|submit|process|complete|finalize)"
    r")"
)

_VERIFY_CALL_RE = re.compile(
    r"(?is)"
    r"(?:\b[A-Za-z0-9_.*\[\]]+\s*(?:\.|::)\s*)?"
    r"(?P<fn>"
    r"VerifySignature|VerifySig|VerifyBytes|VerifyMessage|VerifyDigest|"
    r"VerifyPrehashed|VerifyTranscript|VerifyShare|VerifySignatureShare|"
    r"VerifyGroupSignature|VerifyRoundSignature|VerifyPartialSignature|"
    r"AggregateVerify|FastAggregateVerify|VerifyAggregate|"
    r"VerifyAggregateSignature|VerifyThresholdSignature|"
    r"VerifyASN1|ed25519\.Verify|secp256k1\.VerifySignature|"
    r"ecdsa\.VerifyASN1|ecdsa\.Verify|bls\.Verify|frost\.Verify|"
    r"RecoverCompact|RecoverPubkey|RecoverSignature|IsValidSignature|"
    r"Verify"
    r")\s*\((?P<args>[^;{}]{0,2600})\)"
)

_TRANSCRIPT_BUILD_RE = re.compile(
    r"(?is)\b("
    r"NewTranscript|TranscriptBuilder|SigningTranscript|SigningContext|"
    r"signingContext|newTranscript|BuildTranscript|TranscriptBytes|"
    r"ChallengeBytes|ChallengeScalar|Challenge|"
    r"sha256\.Sum256|sha512\.Sum512|sha3\.Sum256|blake2b\.Sum256|"
    r"blake2s\.Sum256|blake3\.Sum256|tmhash\.Sum|crypto\.Keccak256|"
    r"Keccak256|hashBytes|HashBytes|digestBytes|DigestBytes|"
    r"json\.Marshal|proto\.Marshal|cdc\.Marshal|fmt\.Sprintf|"
    r"bytes\.Join|append"
    r")\b"
)

_DIRECT_HASH_CALL_RE = re.compile(
    r"(?is)\b(?:"
    r"sha256\.Sum256|sha512\.Sum512|sha3\.Sum256|blake2b\.Sum256|"
    r"blake2s\.Sum256|blake3\.Sum256|tmhash\.Sum|crypto\.Keccak256|"
    r"Keccak256|hashBytes|HashBytes|digestBytes|DigestBytes|"
    r"json\.Marshal|proto\.Marshal|cdc\.Marshal|fmt\.Sprintf|bytes\.Join"
    r")\s*\((?P<arg>[^;{}]{0,2600})\)"
)

_ASSIGN_RE = re.compile(
    r"(?is)\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*"
    r"(?P<expr>[^\n;]{0,2600})"
)

_TRANSCRIPT_WRITE_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<method>"
    r"AppendMessage|AppendBytes|AppendUint64|AppendInt64|AppendString|"
    r"AppendPublicKey|AppendCommitment|AppendScalar|AppendPoint|Append|"
    r"Write|WriteString|WriteByte|Extend|Update|Input|Absorb|Bind"
    r")\s*\((?P<arg>[^;{}]{0,2200})\)"
)

_APPEND_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=|:=)\s*append\s*"
    r"\(\s*(?P=buf)\s*,\s*(?P<arg>[^;\n{}]{0,2200})\)"
)

_STATE_EFFECT_RE = re.compile(
    r"(?is)"
    r"\b(?:transfer|safeTransfer|mint|burn|withdraw|release|releaseFunds|"
    r"claim|redeem|settle|credit|debit|execute|dispatch|approve|fulfill|"
    r"finalize|complete|payOut|markUsed|consume|apply|save)\s*\("
    r"|\.("
    r"Transfer|SafeTransfer|Mint|Burn|Withdraw|Release|ReleaseFunds|Claim|"
    r"Redeem|Settle|Credit|Debit|Execute|Dispatch|Approve|Fulfill|"
    r"Finalize|Complete|PayOut|MarkUsed|Consume|Apply|Save|Set|Insert|Remove"
    r")\s*\("
    r"|\[[^\]]+\]\s*=\s*(?:true|false|1|0|[A-Za-z_][A-Za-z0-9_]*)"
)

_SAFE_HELPER_RE = re.compile(
    r"(?i)\b("
    r"domainSeparated|domainBound|domainBoundDigest|domainBoundTranscript|"
    r"bindDomain|bindChain|bindSession|bindPurpose|bindParticipant|"
    r"bindParticipantSet|bindSignerRole|bindSignatureDomain|"
    r"bindSignatureScope|scopedSignatureDigest|scopedTranscript|"
    r"replayBoundTranscript|verifyWithDomain|verifyWithScope|"
    r"ensureDomain|ensureChain|ensureSession|ensureParticipantSet|"
    r"ensureSignerRole|GetSignBytes|SignDoc|SignModeHandler"
    r")\s*\("
)

_PAYLOAD_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"message|msg|payload|payloadHash|payload_hash|call|calldata|recipient|"
    r"receiver|amount|value|asset|assetID|assetId|token|params|order|"
    r"withdrawal|transfer|claim|permit|intent|request|operation|"
    r"instruction|data|body|preimage|signedBytes|signBytes"
    r")\b"
)

_SCOPE_FIELDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "domain",
        re.compile(
            r"(?i)\b("
            r"domainSeparator|domain_separator|domainID|domainId|domain_id|"
            r"domainTag|domain_tag|domainSalt|domain_salt|domainHash|"
            r"domain_hash|transcriptDomain|namespace|protocolID|protocolId|"
            r"protocol_id|appID|appId|app_id|scopeID|scopeId|scope_id"
            r")\b"
        ),
    ),
    (
        "chain_id",
        re.compile(
            r"(?i)\b("
            r"chainID|chainId|chain_id|chainid|networkID|networkId|"
            r"network_id|forkID|forkId|fork_id|genesisHash|genesis_hash|"
            r"sourceChain|source_chain|srcChain|src_chain|destinationChain|"
            r"destination_chain|destChain|dest_chain|dstChain|dst_chain|"
            r"runtimeChain|runtime_chain|paraID|paraId|para_id|"
            r"parachainID|parachainId|parachain_id"
            r")\b"
        ),
    ),
    (
        "session",
        re.compile(
            r"(?i)\b("
            r"sessionID|sessionId|session_id|session|roundID|roundId|"
            r"round_id|signingRound|signing_round|epoch|view|slot|"
            r"checkpointID|checkpointId|checkpoint_id|ceremonyID|"
            r"ceremonyId|ceremony_id|authSession|auth_session"
            r")\b"
        ),
    ),
    (
        "signer_role",
        re.compile(
            r"(?i)\b("
            r"signerRole|signer_role|role|roleID|roleId|role_id|actorRole|"
            r"actor_role|participantRole|participant_role|senderRole|"
            r"sender_role|receiverRole|receiver_role|validatorRole|"
            r"validator_role|coordinatorRole|coordinator_role|operatorRole|"
            r"operator_role"
            r")\b"
        ),
    ),
    (
        "participant_set",
        re.compile(
            r"(?i)\b("
            r"participantSet|participant_set|participantSetHash|"
            r"participant_set_hash|participantBitmap|participant_bitmap|"
            r"signerSet|signer_set|signerSetHash|signer_set_hash|"
            r"signerBitmap|signer_bitmap|validatorSet|validator_set|"
            r"validatorSetHash|validator_set_hash|committee|committeeHash|"
            r"committee_hash|roster|memberSet|member_set|thresholdSet|"
            r"threshold_set"
            r")\b"
        ),
    ),
    (
        "purpose",
        re.compile(
            r"(?i)\b("
            r"purpose|purposeTag|purpose_tag|action|method|operation|"
            r"selector|intentType|intent_type|permitType|permit_type|"
            r"callKind|call_kind|entryPoint|entry_point|instructionTag|"
            r"instruction_tag|messageType|message_type|route|routeID|routeId|"
            r"route_id"
            r")\b"
        ),
    ),
)

_LOAD_BEARING_FIELDS = {
    "chain_id",
    "domain",
    "session",
    "signer_role",
    "participant_set",
    "purpose",
}


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(text: str) -> str:
    return _COMMENT_RE.sub(_blank, text)


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub(_blank, text)


def _field_groups(text: str) -> set[str]:
    clean = _strip_strings(_strip_comments(text))
    return {name for name, pattern in _SCOPE_FIELDS if pattern.search(clean)}


def _assignments(body: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for match in _ASSIGN_RE.finditer(body):
        expr = match.group("expr").strip()
        if expr:
            out[match.group("name")] = expr
    return out


def _transcript_writes(body: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for match in _TRANSCRIPT_WRITE_RE.finditer(body):
        out.setdefault(match.group("buf"), []).append(match.group("arg"))
    for match in _APPEND_RE.finditer(body):
        out.setdefault(match.group("buf"), []).append(match.group("arg"))
    return out


def _expand_expr(
    expr: str,
    assignments: dict[str, str],
    transcript_writes: dict[str, list[str]],
) -> list[str]:
    parts = [expr]
    seen = {expr}
    changed = True

    while changed and len(parts) < 140:
        changed = False
        for item in list(parts):
            for name, assigned in assignments.items():
                if assigned in seen:
                    continue
                if re.search(rf"\b{re.escape(name)}\b", item):
                    parts.append(assigned)
                    seen.add(assigned)
                    changed = True
            for name, writes in transcript_writes.items():
                if not re.search(rf"\b{re.escape(name)}\b", item):
                    continue
                for write in writes:
                    if write in seen:
                        continue
                    parts.append(write)
                    seen.add(write)
                    changed = True

    return parts


def _authenticated_input_text(body: str) -> str:
    assignments = _assignments(body)
    transcript_writes = _transcript_writes(body)
    inputs: list[str] = []

    for match in _TRANSCRIPT_WRITE_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assignments, transcript_writes))
    for match in _APPEND_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assignments, transcript_writes))
    for match in _DIRECT_HASH_CALL_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assignments, transcript_writes))
    for match in _VERIFY_CALL_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("args"), assignments, transcript_writes))
    for expr in assignments.values():
        if _TRANSCRIPT_BUILD_RE.search(expr):
            inputs.extend(_expand_expr(expr, assignments, transcript_writes))

    return "\n".join(inputs)


def _has_signature_domain_replay_shape(name: str, body: str) -> bool:
    if not (_ENTRY_FN_RE.search(name) or _CRYPTO_CONTEXT_RE.search(body)):
        return False
    if not _VERIFY_CALL_RE.search(body):
        return False
    if not _TRANSCRIPT_BUILD_RE.search(body):
        return False
    if not _STATE_EFFECT_RE.search(body):
        return False
    if _SAFE_HELPER_RE.search(body):
        return False
    return True


def _missing_scope_fields(name: str, full_text: str, body: str) -> set[str]:
    visible = _field_groups(f"{name}\n{full_text}")
    if not (visible & _LOAD_BEARING_FIELDS):
        return set()

    auth_inputs = _authenticated_input_text(body)
    if not (auth_inputs.strip() and _PAYLOAD_MATERIAL_RE.search(auth_inputs)):
        return set()

    bound = _field_groups(auth_inputs)
    missing = visible - bound
    if not (missing & _LOAD_BEARING_FIELDS):
        return set()
    return missing


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue

        fn_text = engine.text(fn)
        body_text = engine.text(body)
        body_clean = _strip_comments(body_text)
        body_scan = _strip_strings(body_clean)

        if not _has_signature_domain_replay_shape(name, body_scan):
            continue

        missing = _missing_scope_fields(name, fn_text, body_clean)
        if not missing:
            continue

        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "attack_class": ATTACK_CLASS,
                "verification_tier": VERIFICATION_TIER,
                "submission_posture": SUBMISSION_POSTURE,
                "severity": "high",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` verifies custom signature or transcript bytes "
                    "that omit replay-scope binding for "
                    f"{', '.join(sorted(missing))}. Bind chain id, domain, "
                    "session, signer role, participant set, and purpose into "
                    "the signed bytes before applying state effects. "
                    f"(class: {ATTACK_CLASS}; posture: {SUBMISSION_POSTURE})"
                ),
            }
        )
    return hits
