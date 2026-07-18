"""
bridge-batch-partial-state-or-domain-omission-fire19.

Recall-lift detector for Solidity bridge paths where a batch message can be
partially applied or replayed across the wrong proof domain. Hits are candidate
evidence only. They are not submission-ready proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-batch-partial-state-or-domain-omission-fire19"
DETECTOR_SEVERITY_DEFAULT = "High"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_BRIDGE_CONTEXT_RE = re.compile(
    r"(?i)\b(?:bridge|gateway|crosschain|crossChain|cross[-_ ]?chain|"
    r"inbound|outbound|relay|relayer|dispatch|message|payload|proof|"
    r"merkle|root|domain|chainid|sourceChain|destinationChain|remoteChain|"
    r"command|commands)\b"
)
_BATCH_CONTEXT_RE = re.compile(
    r"(?i)\b(?:batch|batches|commands?|messages?|payloads?)\b"
)
_TRY_CATCH_CONTINUE_RE = re.compile(
    r"(?is)\bfor\s*\([^)]*\)\s*\{[\s\S]*?\btry\b[\s\S]*?\bcatch\b"
    r"\s*(?:\([^)]*\))?\s*\{[^{}]*(?:continue\s*;|return\s+false\s*;|"
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:success|ok|result)[A-Za-z0-9_]*\s*=\s*false)"
)
_CATCH_REVERT_RE = re.compile(
    r"(?is)\bcatch\s*(?:\([^)]*\))?\s*\{[^{}]*\brevert\b"
)
_ATOMIC_BATCH_RE = re.compile(
    r"(?i)\b(?:atomic|allOrNothing|rollback|revertOnFailure|CommandFailed)\b"
)
_STATE_WRITE_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:processed|consumed|used|delivered|finalized|dispatched|"
    r"inboundNonce|outboundNonce)\s*(?:\[[^\]]+\])?\s*(?:=|\+\+|--)|"
    r"\b(?:processed|consumed|used|delivered|finalized|dispatched)\s*\."
    r"(?:set|add)\s*\(|"
    r"\b(?:credit|credits|balance|balances|minted|released|paid|claimed)"
    r"\s*\[[^\]]+\]\s*(?:=|\+=|-=)|"
    r"\b_mint\s*\(|\b_safeMint\s*\(|\b(?:safeTransfer|transfer)\s*\("
    r")"
)
_PROOF_OR_DOMAIN_VALIDATION_RE = re.compile(
    r"(?is)(?:"
    r"require\s*\([^;{}]*(?:MerkleProof|verify|proof|domain|chainid|"
    r"sourceChain|destinationChain|remoteChain|DOMAIN|address\s*\(\s*this\s*\))|"
    r"\b(?:verifyProof|_verifyProof|verifyMessage|_verifyMessage|"
    r"verifyCommitment|_verifyCommitment)\s*\(|"
    r"\b(?:sourceChain|destinationChain|remoteChain|domain|DOMAIN|block\.chainid)"
    r"\s*(?:==|!=)"
    r")"
)
_PROOF_HASH_RE = re.compile(
    r"(?is)(?:MerkleProof\s*\.\s*verify|verifyProof\s*\(|_verifyProof\s*\(|"
    r"keccak256\s*\(\s*abi\s*\.\s*encode(?:Packed)?\s*\(|messageHash|"
    r"leafHash|commitment)"
)
_DOMAIN_BINDING_RE = re.compile(
    r"(?is)(?:DOMAIN|domainSeparator|sourceChain|destinationChain|remoteChain|"
    r"originChain|targetChain|block\.chainid|chainId|chainid|endpointId|"
    r"address\s*\(\s*this\s*\)|verifyingContract)"
)
_OUTBOUND_NAME_RE = re.compile(
    r"(?i)(send|bridge|outbound|quote|dispatch|enqueue|xmit|transmit|relay)"
)
_FEE_CONTEXT_RE = re.compile(
    r"(?i)(executionFee|destinationFee|destFee|relayerFee|remoteFee|"
    r"messageFee|bridgeFee|fee)"
)
_MSG_VALUE_FEE_CHECK_RE = re.compile(
    r"(?is)msg\.value\s*(?:>=|>|==)\s*[^;{}]*(?:executionFee|destinationFee|"
    r"destFee|relayerFee|remoteFee|messageFee|bridgeFee|fee)"
)
_FEE_FLOOR_RE = re.compile(
    r"(?is)(?:MIN_|minimum|Minimum|FLOOR_|floor|feeFloor|"
    r"executionFee\s*>=\s*[A-Za-z_][A-Za-z0-9_]*|"
    r"(?:destinationFee|destFee|relayerFee|remoteFee|messageFee|bridgeFee|fee)"
    r"\s*>\s*0)"
)
_NON_EMPTY_MESSAGE_RE = re.compile(
    r"(?is)(?:payload|message|data|xcm|commands|assets)\s*\.\s*length\s*>\s*0|"
    r"EmptyMessage|InvalidEmpty|NoEmpty"
)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _split_functions(source: str) -> list[tuple[str, str, str, int]]:
    out: list[tuple[str, str, str, int]] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        i = match.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            if source[i] == "(":
                depth_paren += 1
            elif source[i] == ")":
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

        depth = 1
        k = body_start + 1
        while k < len(source) and depth > 0:
            if source[k] == "{":
                depth += 1
            elif source[k] == "}":
                depth -= 1
            k += 1

        header = source[match.start():body_start]
        body = source[body_start + 1:k - 1]
        line = source.count("\n", 0, match.start()) + 1
        out.append((name, header, body, line))
        pos = k
    return out


def _is_bridge_function(name: str, header: str, body: str) -> bool:
    text = f"{name}\n{header}\n{body}"
    return bool(_BRIDGE_CONTEXT_RE.search(text))


def _non_atomic_batch_branch(body: str) -> bool:
    if not _BATCH_CONTEXT_RE.search(body):
        return False
    if not _TRY_CATCH_CONTINUE_RE.search(body):
        return False
    if _CATCH_REVERT_RE.search(body):
        return False
    if _ATOMIC_BATCH_RE.search(body):
        return False
    return True


def _state_write_before_validation_branch(body: str) -> bool:
    write = _STATE_WRITE_RE.search(body)
    validation = _PROOF_OR_DOMAIN_VALIDATION_RE.search(body)
    if write is None or validation is None:
        return False
    return write.start() < validation.start()


def _domainless_proof_branch(body: str) -> bool:
    if not _PROOF_HASH_RE.search(body):
        return False
    if _DOMAIN_BINDING_RE.search(body):
        return False
    return True


def _zero_fee_outbound_branch(name: str, body: str) -> bool:
    if not _OUTBOUND_NAME_RE.search(name):
        return False
    if not _FEE_CONTEXT_RE.search(body):
        return False
    if not _MSG_VALUE_FEE_CHECK_RE.search(body):
        return False
    if _FEE_FLOOR_RE.search(body):
        return False
    if _NON_EMPTY_MESSAGE_RE.search(body):
        return False
    return True


def _finding(file_path: str, line: int, function: str, branch: str) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            f"{branch} in bridge proof-domain batch path. "
            "Treat as candidate evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for name, header, body, line in _split_functions(code):
        if not _is_bridge_function(name, header, body):
            continue

        if _non_atomic_batch_branch(body):
            findings.append(
                _finding(file_path, line, name, "non-atomic try-catch batch continuation")
            )
        if _state_write_before_validation_branch(body):
            findings.append(
                _finding(file_path, line, name, "state write before proof or domain validation")
            )
        if _domainless_proof_branch(body):
            findings.append(
                _finding(file_path, line, name, "proof digest omits chain or domain binding")
            )
        if _zero_fee_outbound_branch(name, body):
            findings.append(
                _finding(file_path, line, name, "outbound message fee floor omitted")
            )
    return findings
