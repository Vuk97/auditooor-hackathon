"""
bridge-proof-consume-once-fire28.

Solidity recall-lift detector for bridge payout and settlement paths that
verify proof material and release value without a consume-once guard and write
before custody leaves. This is candidate evidence only: a hit needs bridge
context, proof verification, value release, and no local consumed, processed,
claimed, spent, or nullifier ledger protection before the transfer or mint.

Lineage:
- reference/big_loss_templates/bridge_proof_domain_consume_once.json
- reference/patterns.dsl/bridge-proof-payout-missing-consume-once-fire9.yaml
- reference/patterns.dsl/bridge-replay-key-omits-chain-domain.yaml
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-proof-consume-once-fire28"
DETECTOR_SEVERITY_DEFAULT = "High"


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
_ENTRYPOINT_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b")
_VIEW_OR_PURE_RE = re.compile(r"\b(?:view|pure)\b", re.IGNORECASE)
_SOURCE_BRIDGE_CONTEXT_RE = re.compile(
    r"\b(?:bridge|gateway|crosschain|crossChain|cross[-_ ]?chain|portal|"
    r"relay|relayer|dispatcher|withdraw|withdrawal|payout|settle|proof|"
    r"message|export|root|leaf|merkle|inbound|outbound|domain|chain)\b",
    re.IGNORECASE,
)
_PAYOUT_NAME_RE = re.compile(
    r"\b(?:claim|settle|finalize|finalizeWithdrawal|withdraw|release|"
    r"payout|payOut|process|execute|redeem|mint|claimExport|processExport|"
    r"dispatch)\b",
    re.IGNORECASE,
)
_PROOF_VERIFY_RE = re.compile(
    r"\b(?:MerkleProof\s*\.\s*verify|MerkleProof\s*\.\s*multiProofVerify|"
    r"verifyProof|verifyMerkleProof|verifyMessage|verifyWithdrawal|"
    r"verifyReceipt|verifyInclusion|verifyRoot|verifyCommitment|"
    r"verify.*Proof|_verify.*Proof|isValidProof|checkProof|"
    r"proof\s*\.\s*verify|[A-Za-z_][A-Za-z0-9_]*\s*\.\s*"
    r"verify(?:Message|Proof|Withdrawal|Receipt|Inclusion|Root|Commitment)?"
    r"\s*\()",
    re.IGNORECASE | re.DOTALL,
)
_PROOF_MATERIAL_RE = re.compile(
    r"\b(?:proof|merkleProof|leaf|root|stateRoot|merkleRoot|messageHash|"
    r"payloadHash|nonce|txid|transactionId|transferId|withdrawalHash|"
    r"exportId|sourceExport|commitment)\b",
    re.IGNORECASE,
)
_VALUE_RELEASE_RE = re.compile(
    r"\.\s*(?:safeTransfer|transfer|send)\s*\(|"
    r"\b(?:safeTransfer|SafeERC20\s*\.\s*safeTransfer)\s*\(|"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\([^;{}]*\)\s*\.\s*"
    r"(?:safeTransfer|transfer)\s*\(|"
    r"\b(?:_mint|mint)\s*\(|"
    r"\.\s*call\s*\{[^{};]*value\s*:",
    re.IGNORECASE | re.DOTALL,
)
_CONSUME_WORDS = (
    r"consumed|processed|spent|used|claimed|executed|completed|replayed|"
    r"nullifier|messageStatus|usedProof|processedMessages|processedTxids|"
    r"consumedProofs|consumedLeaves|consumedMessages|spentNonces|"
    r"claimedWithdrawals|isProcessed|alreadyProcessed|messageProcessed|"
    r"withdrawalClaimed"
)
_CONSUME_WRITE_RE = re.compile(
    rf"\b(?:{_CONSUME_WORDS})[A-Za-z0-9_]*\s*(?:\[[^\]]+\]\s*){{1,4}}"
    r"=\s*(?:true|1|[A-Za-z_][A-Za-z0-9_]*\s*\.\s*"
    r"(?:Consumed|Processed|Spent|Used|Claimed|Executed|Completed))\b|"
    r"\b(?:mark|_mark|set|_set)?(?:Consumed|Processed|Spent|Used|Claimed|"
    r"Executed|Completed)[A-Za-z0-9_]*\s*\(|"
    r"\b(?:consume|_consume)(?:Proof|Leaf|Message|Nonce|Tx|Txid|"
    r"Withdrawal|Export|Nullifier)?[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_CONSUME_CHECK_RE = re.compile(
    rf"\b(?:require|if|assert)\s*\([^;{{}}]*(?:{_CONSUME_WORDS})"
    r"[A-Za-z0-9_]*\s*(?:\[|\(|\.)[^;{}]*\)",
    re.IGNORECASE | re.DOTALL,
)


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


def _context(fn: FunctionSlice) -> str:
    return f"{fn.name}\n{fn.header}\n{fn.body}"


def _line_for(fn: FunctionSlice, pos: int) -> int:
    return fn.body_line + fn.body.count("\n", 0, pos)


def _first_value_release_after_verify(body: str) -> re.Match[str] | None:
    verify = _PROOF_VERIFY_RE.search(body)
    if verify is None:
        return None
    return _VALUE_RELEASE_RE.search(body, verify.end())


def _has_prerelease_consume_guard_and_write(body: str, value_pos: int) -> bool:
    prefix = body[:value_pos]
    return bool(_CONSUME_CHECK_RE.search(prefix)) and bool(_CONSUME_WRITE_RE.search(prefix))


def _has_late_consume_write(body: str, value_pos: int) -> bool:
    return _CONSUME_WRITE_RE.search(body, value_pos) is not None


def _is_candidate_bridge_payout(fn: FunctionSlice) -> bool:
    text = _context(fn)
    return (
        bool(_ENTRYPOINT_HEADER_RE.search(fn.header))
        and not bool(_VIEW_OR_PURE_RE.search(fn.header))
        and bool(_PAYOUT_NAME_RE.search(fn.name) or _SOURCE_BRIDGE_CONTEXT_RE.search(text))
        and bool(_PROOF_VERIFY_RE.search(text))
        and bool(_PROOF_MATERIAL_RE.search(text))
    )


def _reason(fn: FunctionSlice, value_pos: int) -> str:
    prefix = fn.body[:value_pos]
    reasons: list[str] = []
    if _has_late_consume_write(fn.body, value_pos):
        reasons.append("consume write occurs after value release")
    elif _CONSUME_CHECK_RE.search(prefix) and not _CONSUME_WRITE_RE.search(prefix):
        reasons.append("consume-once check exists without pre-release write")
    elif _CONSUME_WRITE_RE.search(prefix) and not _CONSUME_CHECK_RE.search(prefix):
        reasons.append("consume write exists without pre-release guard")
    else:
        reasons.append("no consume-once guard/write before value release")
    if re.search(r"\b(?:MerkleProof|merkleRoot|stateRoot|leaf|proof)\b", _context(fn), re.IGNORECASE):
        reasons.append("proof-backed payout")
    return ", ".join(reasons)


def _finding(file_path: str, line: int, function: str, reason: str) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            f"{reason} in bridge proof payout path. Proof material is verified "
            "before transfer, mint, or native-value release, but the proof, "
            "leaf, message, withdrawal, txid, or replay key is not fully "
            "checked and consumed before custody leaves. Candidate evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    if not _SOURCE_BRIDGE_CONTEXT_RE.search(code):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _is_candidate_bridge_payout(fn):
            continue
        value_release = _first_value_release_after_verify(fn.body)
        if value_release is None:
            continue
        if _has_prerelease_consume_guard_and_write(fn.body, value_release.start()):
            continue
        findings.append(
            _finding(
                file_path,
                _line_for(fn, value_release.start()),
                fn.name,
                _reason(fn, value_release.start()),
            )
        )
    return findings
