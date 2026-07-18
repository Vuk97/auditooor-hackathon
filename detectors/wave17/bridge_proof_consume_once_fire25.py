"""
bridge-proof-consume-once-fire25.

Solidity recall-lift detector for bridge proof consumers that verify proof or
message material and then externally dispatch the message before an exactly-once
consume ledger is written. This is candidate evidence only: a hit needs bridge
context, proof verification, external dispatch, and no consumed or processed
state write before the dispatch boundary.

Lineage:
- Fire9 bridge-proof-payout-missing-consume-once catches proof payouts with no
  consume-once ledger at all.
- Fire24 bridge-proof-route-consume catches weak consumed keys composed with
  mutable routes and dispatch failures.
- Fire25 CC covers the same-class gap where the consume ledger is absent or is
  written only after external dispatch, especially in batch try/catch loops.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-proof-consume-once-fire25"
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
_BRIDGE_CONTEXT_RE = re.compile(
    r"\b(?:bridge|gateway|crosschain|crossChain|cross[-_ ]?chain|relay|"
    r"relayer|message|dispatch|inbound|outbound|proof|root|commitment|"
    r"packet|payload|nonce|lane|endpoint|domain|chain)\b",
    re.IGNORECASE,
)
_PROOF_VERIFY_RE = re.compile(
    r"\b(?:MerkleProof\s*\.\s*verify|verifyProof|verifyMessage|"
    r"verifyPacket|verifyPayload|verifyReceipt|verifyRoot|verifyInclusion|"
    r"verifyCommitment|isValidProof|checkProof|proof\s*\.\s*verify|"
    r"[A-Za-z_][A-Za-z0-9_]*Verifier\s*\([^;{}]*\)\s*\.\s*verify|"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\.\s*verify(?:Message|Proof|Packet|Payload|Root)?"
    r"\s*\()",
    re.IGNORECASE | re.DOTALL,
)
_DISPATCH_RE = re.compile(
    r"\.\s*(?:call|delegatecall|functionCall)\s*(?:\{|\()|"
    r"\btry\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^;{}]*\)\s*\.\s*"
    r"(?:dispatch|deliver|execute|handle|receiveMessage|onMessage|"
    r"onBridgeMessage|lzReceive|processMessage)\s*\(|"
    r"\b(?:dispatcher|receiver|target|executor|adapter|router|endpoint)"
    r"\s*\.\s*(?:dispatch|deliver|execute|handle|receiveMessage|"
    r"onMessage|onBridgeMessage|lzReceive|processMessage)\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_CONSUME_WRITE_RE = re.compile(
    r"\b(?:consumed|processed|used|delivered|finalized|executed|relayed|"
    r"dispatched|seen|spent|claimed|completed|messageConsumed|"
    r"receiptConsumed)[A-Za-z0-9_]*\s*(?:\[[^\]]+\]\s*){1,4}=\s*"
    r"(?:true|[A-Za-z_][A-Za-z0-9_]*\s*\.\s*"
    r"(?:Consumed|Processed|Delivered|Executed|Complete))\b|"
    r"\b(?:mark|_mark|set|_set)?(?:Consumed|Processed|Used|Delivered|"
    r"Finalized|Executed|Relayed|Dispatched|Spent|Claimed|Completed)"
    r"[A-Za-z0-9_]*\s*\(|"
    r"\b(?:consume|_consume)(?:Message|Packet|Nonce|Root|Leaf|Proof|"
    r"Receipt|Withdrawal|Tx|Txid)?[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_CONSUME_CHECK_RE = re.compile(
    r"\b(?:require|if)\s*\([^;{}]*(?:consumed|processed|used|delivered|"
    r"finalized|executed|spent|claimed|completed|messageConsumed|"
    r"receiptConsumed)[A-Za-z0-9_]*\s*(?:\[|\.)[^;{}]*\)",
    re.IGNORECASE | re.DOTALL,
)
_BATCH_CONTEXT_RE = re.compile(r"\b(?:for\s*\(|while\s*\(|batch|messages|packets|payloads)\b", re.IGNORECASE)
_TRY_CATCH_CONTINUE_RE = re.compile(
    r"\btry\b[\s\S]*?\bcatch\s*(?:\([^)]*\))?\s*\{[^{}]*"
    r"(?:continue\s*;|return\s*;|return\s+false\s*;|emit\s+"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\()",
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


def _first_dispatch_after_verify(body: str) -> re.Match[str] | None:
    verify = _PROOF_VERIFY_RE.search(body)
    if verify is None:
        return None
    return _DISPATCH_RE.search(body, verify.end())


def _has_pre_dispatch_consume(body: str, dispatch_pos: int) -> bool:
    for match in _CONSUME_WRITE_RE.finditer(body):
        if match.start() < dispatch_pos:
            return True
        if match.start() >= dispatch_pos:
            return False
    return False


def _has_late_consume(body: str, dispatch_pos: int) -> bool:
    return _CONSUME_WRITE_RE.search(body, dispatch_pos) is not None


def _is_bridge_proof_consumer(fn: FunctionSlice) -> bool:
    text = _context(fn)
    return (
        bool(_ENTRYPOINT_HEADER_RE.search(fn.header))
        and bool(_BRIDGE_CONTEXT_RE.search(text))
        and bool(_PROOF_VERIFY_RE.search(text))
    )


def _reason(fn: FunctionSlice, dispatch_pos: int) -> str:
    reasons: list[str] = []
    if _has_late_consume(fn.body, dispatch_pos):
        reasons.append("consume write occurs after external dispatch")
    else:
        reasons.append("no consume write before external dispatch")
    if _BATCH_CONTEXT_RE.search(_context(fn)):
        reasons.append("batch path")
    if _TRY_CATCH_CONTINUE_RE.search(fn.body):
        reasons.append("try/catch continuation")
    if _CONSUME_CHECK_RE.search(fn.body[:dispatch_pos]) and not _has_pre_dispatch_consume(fn.body, dispatch_pos):
        reasons.append("already-consumed check without pre-dispatch write")
    return ", ".join(reasons)


def _finding(file_path: str, line: int, function: str, reason: str) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            f"{reason} in bridge proof consume path. Proof material is "
            "verified before an external message dispatch, but the message "
            "hash, nonce, root, or packet id is not consumed before that "
            "dispatch boundary. Candidate evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _is_bridge_proof_consumer(fn):
            continue
        dispatch = _first_dispatch_after_verify(fn.body)
        if dispatch is None:
            continue
        if _has_pre_dispatch_consume(fn.body, dispatch.start()):
            continue
        findings.append(_finding(file_path, _line_for(fn, dispatch.start()), fn.name, _reason(fn, dispatch.start())))
    return findings
