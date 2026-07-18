"""
bridge-batch-dispatch-partial-state-fire29.

Solidity recall-lift detector for bridge batch dispatchers that process
multiple inbound messages in one verified batch, catch per-message dispatch
failures, and continue after writing consumed, credited, or settled state for
only part of the batch.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:1fbd7a4998da1f42
- context_pack_hash: 1fbd7a4998da1f424cce0858c69a5dd246edb458f1cb9f1927dd25e36d73cb98
- source refs:
  - reference/patterns.dsl/bridge-batch-dispatch-try-catch-continue-partial-state.yaml
  - reference/patterns.dsl/bridge-proof-domain-bypass-umbrella.yaml
  - reference/big_loss_templates/bridge_proof_domain.json
- attack_class: bridge-proof-domain-bypass

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-batch-dispatch-partial-state-fire29"
DETECTOR_SEVERITY_DEFAULT = "High"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
COVERAGE_CLAIM = "detector_fixture_smoke_only"
PROMOTION_ALLOWED = False


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


@dataclass
class LoopSlice:
    header: str
    body: str
    start: int
    end: int
    body_line: int


_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_FOR_HEADER_RE = re.compile(r"\b(?:for|while)\s*\(")
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b")
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b")
_BRIDGE_CONTEXT_RE = re.compile(
    r"\b(?:bridge|gateway|portal|crosschain|crossChain|cross[-_ ]?chain|"
    r"inbound|outbound|relay|relayer|message|packet|payload|dispatch|"
    r"proof|root|commitment|receipt|nonce|domain|chain|route|lane|"
    r"destination|source|settle|credit)\b",
    re.IGNORECASE,
)
_BATCH_CONTEXT_RE = re.compile(
    r"\b(?:batch|batches|messages|msgs|packets|commands|payloads|items)\b",
    re.IGNORECASE,
)
_PROOF_CONTEXT_RE = re.compile(
    r"\b(?:proof|proofs|root|stateRoot|messageRoot|receiptRoot|leaf|"
    r"leafHash|MerkleProof|verifyProof|verifyMessage|verifyRoot|"
    r"verifyCommitment|commitment)\b",
    re.IGNORECASE,
)
_CATCH_BLOCK_RE = re.compile(
    r"\bcatch\s*(?:\([^)]*\))?\s*\{(?P<body>[^{}]*)\}",
    re.IGNORECASE | re.DOTALL,
)
_NONREVERTING_CATCH_RE = re.compile(
    r"\b(?:continue\s*;|return\s+false\s*;|return\s*;|"
    r"(?:success|ok|delivered|settled|accepted)\s*=\s*false|"
    r"emit\s+[A-Za-z_][A-Za-z0-9_]*(?:Failed|Skipped|Error|Failure)\s*\()",
    re.IGNORECASE | re.DOTALL,
)
_CATCH_REVERT_RE = re.compile(
    r"\b(?:revert\b|require\s*\(\s*false|assembly\s*\{[^{}]*\brevert\b)",
    re.IGNORECASE | re.DOTALL,
)
_ROLLBACK_RE = re.compile(
    r"\b(?:delete\s+|"
    r"(?:consumed|processed|used|delivered|finalized|executed|settled|"
    r"credited|claimed|completed)[A-Za-z0-9_]*\s*(?:\[[^\]]+\]\s*){1,4}"
    r"=\s*(?:false|0)|"
    r"\.\s*(?:unset|clear|remove)\s*\([^;{}]*(?:nonce|message|packet|"
    r"payload|receipt|processed|consumed|settled|credit)[^;{}]*\))",
    re.IGNORECASE | re.DOTALL,
)
_ATOMIC_GUARD_RE = re.compile(
    r"\b(?:allOrNothing|atomicBatch|batchMustSucceed|BatchMustSucceed|"
    r"BatchDispatchFailed|revert\s+[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"require\s*\(\s*(?:success|ok|allSucceeded|batchSucceeded|"
    r"batchSuccess)\s*[,)]|"
    r"if\s*\(\s*!\s*(?:success|ok|allSucceeded|batchSucceeded|"
    r"batchSuccess)\s*\)\s*(?:\{[^{}]*\brevert\b|\brevert\b))",
    re.IGNORECASE | re.DOTALL,
)
_MARKER_WRITE_RE = re.compile(
    r"\b(?:consumed|processed|used|delivered|finalized|executed|"
    r"settled|claimed|completed|messageConsumed|receiptConsumed)"
    r"[A-Za-z0-9_]*\s*(?:\[[^\]]+\]\s*){1,4}=\s*(?:true|1)\b|"
    r"\b(?:mark|_mark|set|_set)?(?:Consumed|Processed|Used|Delivered|"
    r"Finalized|Executed|Settled|Claimed|Completed)[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_CREDIT_OR_SETTLEMENT_RE = re.compile(
    r"\b(?:credited|credits|balances|settled|settlements|claimable|claims|"
    r"escrow|released|minted|receipts)[A-Za-z0-9_]*\s*(?:\[[^\]]+\]\s*){1,4}"
    r"(?:\+=|-=|=)|"
    r"\b(?:_mint|mint|safeTransfer|transfer|release|credit|settle)"
    r"[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_STATE_WRITE_RE = re.compile(
    _MARKER_WRITE_RE.pattern + r"|" + _CREDIT_OR_SETTLEMENT_RE.pattern,
    re.IGNORECASE | re.DOTALL,
)
_TRY_RE = re.compile(r"\btry\b", re.IGNORECASE)
_SKIP_CONTRACT_RE = re.compile(r"(?i)\b(mock|test|fixture)\b")


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


def _split_loops(fn: FunctionSlice) -> list[LoopSlice]:
    out: list[LoopSlice] = []
    pos = 0
    while True:
        match = _FOR_HEADER_RE.search(fn.body, pos)
        if match is None:
            break
        i = match.end()
        depth_paren = 1
        while i < len(fn.body) and depth_paren > 0:
            char = fn.body[i]
            if char == "(":
                depth_paren += 1
            elif char == ")":
                depth_paren -= 1
            i += 1
        body_start = -1
        j = i
        while j < len(fn.body):
            if fn.body[j] == ";":
                break
            if fn.body[j] == "{":
                body_start = j
                break
            j += 1
        if body_start < 0:
            pos = max(i, j)
            continue

        body, end_pos = _extract_balanced_block(fn.body, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = fn.body[match.start():body_start]
        body_line = fn.body_line + fn.body.count("\n", 0, body_start + 1)
        out.append(
            LoopSlice(
                header=header,
                body=body,
                start=match.start(),
                end=end_pos,
                body_line=body_line,
            )
        )
        pos = end_pos
    return out


def _context(fn: FunctionSlice) -> str:
    return f"{fn.name}\n{fn.header}\n{fn.body}"


def _line_for(loop: LoopSlice, match: re.Match[str]) -> int:
    return loop.body_line + loop.body.count("\n", 0, match.start())


def _is_callable_bridge_batch(fn: FunctionSlice) -> bool:
    text = _context(fn)
    if not _CALLABLE_HEADER_RE.search(fn.header) or _VIEW_HEADER_RE.search(fn.header):
        return False
    if _SKIP_CONTRACT_RE.search(text):
        return False
    return (
        bool(_BRIDGE_CONTEXT_RE.search(text))
        and bool(_BATCH_CONTEXT_RE.search(text))
        and bool(_PROOF_CONTEXT_RE.search(text))
    )


def _state_write_reason(prefix: str) -> str:
    reasons: list[str] = []
    if _MARKER_WRITE_RE.search(prefix):
        reasons.append("consumed or settled marker written before failure is atomic")
    if _CREDIT_OR_SETTLEMENT_RE.search(prefix):
        reasons.append("credit or settlement state can be partially applied")
    return "; ".join(reasons)


def _non_atomic_catch(loop: LoopSlice, catch: re.Match[str], fn_tail: str) -> bool:
    catch_text = catch.group(0)
    after_catch = loop.body[catch.end():]
    if not _NONREVERTING_CATCH_RE.search(catch_text):
        return False
    if _CATCH_REVERT_RE.search(catch_text):
        return False
    if _ROLLBACK_RE.search(catch_text) or _ROLLBACK_RE.search(after_catch):
        return False
    if _ATOMIC_GUARD_RE.search(after_catch) or _ATOMIC_GUARD_RE.search(fn_tail):
        return False
    return True


def _partial_state_catch(fn: FunctionSlice, loop: LoopSlice) -> tuple[re.Match[str], str] | None:
    if not _TRY_RE.search(loop.body):
        return None
    if not _BRIDGE_CONTEXT_RE.search(loop.body):
        return None

    fn_tail = fn.body[loop.end:]
    for catch in _CATCH_BLOCK_RE.finditer(loop.body):
        if not _non_atomic_catch(loop, catch, fn_tail):
            continue
        prefix = loop.body[:catch.start()]
        if not _TRY_RE.search(prefix):
            continue
        state_write = _STATE_WRITE_RE.search(prefix)
        if state_write is None:
            continue
        reason = _state_write_reason(prefix)
        if not reason:
            continue
        return state_write, reason
    return None


def _finding(file_path: str, line: int, function: str, reason: str) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            f"{reason} in bridge batch dispatcher with per-message catch and "
            "continue. The batch can leave inconsistent consumed, credited, "
            "or settled state instead of reverting or rolling back the "
            "failed message. NOT_SUBMIT_READY: detector fixture smoke "
            "evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _is_callable_bridge_batch(fn):
            continue
        for loop in _split_loops(fn):
            partial = _partial_state_catch(fn, loop)
            if partial is None:
                continue
            state_write, reason = partial
            findings.append(_finding(file_path, _line_for(loop, state_write), fn.name, reason))
            break
    return findings


__all__ = [
    "scan",
    "Finding",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
]
