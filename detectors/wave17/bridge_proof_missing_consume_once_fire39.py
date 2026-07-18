"""
bridge-proof-missing-consume-once-fire39.

verification_tier: tier-3-synthetic-taxonomy-anchored
attack_class: signature-replay-cross-domain
context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c
context_pack_hash: cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8
MCP receipt: .auditooor/memory_context_receipt.json
NOT_SUBMIT_READY
R40/R76/R80 caveat: detector hits are source-review candidates only, not proof.

Solidity recall-lift detector for bridge proof or signature consumers that
verify cross-domain material and then release value or dispatch a message
without a pre-effect consume-once write keyed by a domain-bound replay key.

The detector intentionally accepts only source-review candidates. A safe
implementation must have all three before custody leaves or the message is
dispatched:

1. A consumed or processed check.
2. A consumed or processed write.
3. A replay key that binds source domain, destination or live chain context,
   and the local destination contract.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-proof-missing-consume-once-fire39"
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
_BRIDGE_CONTEXT_RE = re.compile(
    r"\b(?:bridge|gateway|crosschain|crossChain|cross[-_ ]?chain|portal|"
    r"relay|relayer|router|route|message|dispatch|withdraw|withdrawal|"
    r"proof|root|leaf|merkle|packet|payload|nonce|domain|chain|lane|"
    r"endpoint)\b",
    re.IGNORECASE,
)
_DOMAIN_CONTEXT_RE = re.compile(
    r"\b(?:source|src|origin|remote|from|destination|dest|dst|target|"
    r"local|to)\w*(?:Chain|ChainId|Domain|DomainId|NetworkId|Eid|chain|"
    r"domain)\b|block\.chainid|DOMAIN_SEPARATOR|domainSeparator|"
    r"_domainSeparatorV4|address\s*\(\s*this\s*\)",
    re.IGNORECASE,
)
_PROOF_OR_SIGNATURE_RE = re.compile(
    r"\b(?:MerkleProof\s*\.\s*verify|MerkleProof\s*\.\s*multiProofVerify|"
    r"verifyProof|verifyMerkleProof|verifyMessage|verifyWithdrawal|"
    r"verifyReceipt|verifyPacket|verifyPayload|verifyInclusion|verifyRoot|"
    r"verifyCommitment|verifySignature|verify.*Proof|_verify.*Proof|"
    r"isValidProof|checkProof|proof\s*\.\s*verify|ECDSA\s*\.\s*recover|"
    r"SignatureChecker\s*\.\s*isValidSignatureNow|isValidSignature|"
    r"ecrecover|_hashTypedDataV4|DOMAIN_SEPARATOR)\b",
    re.IGNORECASE | re.DOTALL,
)
_EFFECT_RE = re.compile(
    r"\.\s*(?:safeTransfer|transfer|send|safeTransferFrom|transferFrom)"
    r"\s*\(|"
    r"\b(?:safeTransfer|safeTransferFrom|SafeERC20\s*\.\s*safeTransfer)"
    r"\s*\(|"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\([^;{}]*\)\s*\.\s*"
    r"(?:safeTransfer|transfer|safeTransferFrom|transferFrom)\s*\(|"
    r"\b(?:_mint|mint)\s*\(|"
    r"\.\s*call\s*\{[^{};]*value\s*:|"
    r"\b(?:dispatcher|receiver|target|executor|adapter|router|endpoint)"
    r"\s*\.\s*(?:dispatch|deliver|execute|handle|receiveMessage|"
    r"onMessage|onBridgeMessage|lzReceive|processMessage)\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_CONSUME_WORDS = (
    r"consumed|processed|used|spent|claimed|executed|completed|relayed|"
    r"delivered|finalized|seen|replayed|nullifier|messageStatus|usedProof|"
    r"processedMessages|processedTxids|consumedProofs|consumedLeaves|"
    r"consumedMessages|spentNonces|claimedWithdrawals|messageProcessed|"
    r"withdrawalClaimed"
)
_CONSUME_CHECK_RE = re.compile(
    rf"\b(?:require|if|assert)\s*\([^;{{}}]*(?:{_CONSUME_WORDS})"
    r"[A-Za-z0-9_]*\s*(?:\[|\.)[^;{}]*\)",
    re.IGNORECASE | re.DOTALL,
)
_CONSUME_WRITE_RE = re.compile(
    rf"\b(?:{_CONSUME_WORDS})[A-Za-z0-9_]*\s*(?:\[[^\]]+\]\s*){{1,4}}"
    r"=\s*(?:true|1|[A-Za-z_][A-Za-z0-9_]*\s*\.\s*"
    r"(?:Consumed|Processed|Used|Spent|Claimed|Executed|Completed))\b|"
    r"\b(?:mark|_mark|set|_set)?(?:Consumed|Processed|Used|Spent|Claimed|"
    r"Executed|Completed)[A-Za-z0-9_]*\s*\(|"
    r"\b(?:consume|_consume)(?:Proof|Leaf|Message|Nonce|Tx|Txid|"
    r"Withdrawal|Packet|Payload|Root|Nullifier)?[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_CONSUME_MAPPING_ACCESS_RE = re.compile(
    rf"\b(?:{_CONSUME_WORDS})[A-Za-z0-9_]*\s*\[\s*(?P<key>[^\]]+)\s*\]",
    re.IGNORECASE | re.DOTALL,
)
_HASH_ASSIGN_RE = re.compile(
    r"\b(?:bytes32\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*"
    r"(?:Key|Id|ID|Hash|Digest|Nonce|Leaf|Receipt|Message)?)\s*=\s*"
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,1800}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_SOURCE_DOMAIN_RE = re.compile(
    r"\b(?:source|src|origin|remote|from)\w*(?:Chain|ChainId|Domain|"
    r"DomainId|NetworkId|Eid|chain|domain)\b",
    re.IGNORECASE,
)
_DEST_DOMAIN_RE = re.compile(
    r"\b(?:destination|dest|dst|target|local|to)\w*(?:Chain|ChainId|"
    r"Domain|DomainId|NetworkId|Eid|chain|domain)\b",
    re.IGNORECASE,
)
_LIVE_CHAIN_RE = re.compile(
    r"\b(?:block\.chainid|_chainId\s*\(\s*\)|getChainId\s*\(\s*\)|"
    r"chainid\s*\(\s*\))\b",
    re.IGNORECASE,
)
_LOCAL_CONTRACT_RE = re.compile(
    r"(?:address\s*\(\s*this\s*\)|\b(?:verifyingContract|DOMAIN_SEPARATOR|"
    r"domainSeparator|_domainSeparatorV4)\b)",
    re.IGNORECASE,
)
_HARDCODED_CHAIN_RE = re.compile(
    r"\b(?:uint(?:256)?\s*\(\s*)?1\s*\)?\b",
    re.IGNORECASE,
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


def _first_effect_after_verify(body: str) -> re.Match[str] | None:
    verify = _PROOF_OR_SIGNATURE_RE.search(body)
    if verify is None:
        return None
    return _EFFECT_RE.search(body, verify.end())


def _assigned_expr_before(body: str, name: str, pos: int) -> str:
    found = ""
    bare_name = name.strip()
    for match in _HASH_ASSIGN_RE.finditer(body[:pos]):
        if match.group("name") == bare_name:
            found = match.group("expr")
    return found


def _consume_key_exprs_before(body: str, effect_pos: int) -> list[str]:
    exprs: list[str] = []
    prefix = body[:effect_pos]
    for match in _CONSUME_MAPPING_ACCESS_RE.finditer(prefix):
        key = match.group("key").strip()
        assigned = _assigned_expr_before(body, key, match.start())
        exprs.append(assigned or key)
    return exprs


def _has_domain_bound_replay_key(body: str, effect_pos: int) -> bool:
    for expr in _consume_key_exprs_before(body, effect_pos):
        if _is_domain_bound_replay_key(expr):
            return True
    return False


def _is_domain_bound_replay_key(expr: str) -> bool:
    if not expr:
        return False
    has_source = bool(_SOURCE_DOMAIN_RE.search(expr))
    has_destination = bool(_DEST_DOMAIN_RE.search(expr) or _LIVE_CHAIN_RE.search(expr))
    has_local_contract = bool(_LOCAL_CONTRACT_RE.search(expr))
    has_hardcoded_chain_only = bool(_HARDCODED_CHAIN_RE.search(expr)) and not bool(_LIVE_CHAIN_RE.search(expr))
    return has_source and has_destination and has_local_contract and not has_hardcoded_chain_only


def _pre_effect_replay_state(body: str, effect_pos: int) -> tuple[bool, bool, bool]:
    prefix = body[:effect_pos]
    has_check = bool(_CONSUME_CHECK_RE.search(prefix))
    has_write = bool(_CONSUME_WRITE_RE.search(prefix))
    has_domain_key = _has_domain_bound_replay_key(body, effect_pos)
    return has_check, has_write, has_domain_key


def _is_bridge_verifier_effect(fn: FunctionSlice) -> bool:
    text = _context(fn)
    return (
        bool(_ENTRYPOINT_HEADER_RE.search(fn.header))
        and not bool(_VIEW_OR_PURE_RE.search(fn.header))
        and bool(_BRIDGE_CONTEXT_RE.search(text))
        and bool(_DOMAIN_CONTEXT_RE.search(text))
        and bool(_PROOF_OR_SIGNATURE_RE.search(text))
    )


def _reason(body: str, effect_pos: int) -> str:
    has_check, has_write, has_domain_key = _pre_effect_replay_state(body, effect_pos)
    reasons: list[str] = []
    if not has_check and not has_write:
        reasons.append("no consume-once check or write before effect")
    elif has_check and not has_write:
        reasons.append("consume-once check without pre-effect write")
    elif has_write and not has_check:
        reasons.append("consume-once write without pre-effect guard")
    elif not has_domain_key:
        reasons.append("consume key is not bound to source domain, destination chain, and local contract")

    if _CONSUME_WRITE_RE.search(body, effect_pos):
        reasons.append("late consume write")
    if bool(_HARDCODED_CHAIN_RE.search(body)) and not bool(_LIVE_CHAIN_RE.search(body)):
        reasons.append("hardcoded chain id context")
    return ", ".join(reasons)


def _finding(file_path: str, line: int, function: str, reason: str) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            f"{reason} in bridge proof or signature consume path. Cross-domain "
            "proof or signature material is accepted before value release or "
            "message dispatch, but replay protection is missing, late, or not "
            "domain-bound. Source-review candidates only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    if not _BRIDGE_CONTEXT_RE.search(code):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _is_bridge_verifier_effect(fn):
            continue
        effect = _first_effect_after_verify(fn.body)
        if effect is None:
            continue
        has_check, has_write, has_domain_key = _pre_effect_replay_state(fn.body, effect.start())
        if has_check and has_write and has_domain_key:
            continue
        findings.append(
            _finding(
                file_path,
                _line_for(fn, effect.start()),
                fn.name,
                _reason(fn.body, effect.start()),
            )
        )
    return findings
