"""
bridge-proof-domain-batch-dispatch-fire23.

Solidity recall-lift detector for batch bridge dispatch paths that mark a
message/root/nonce as consumed before the message is bound to the expected
bridge domain and before a failed dispatch is known to have succeeded or
reverted atomically.

This is candidate evidence only. It is not a generic CEI detector: a hit must
show bridge batch context, proof/root context, visible source or destination
domain fields, a weak consume key, and a non-reverting skip/continue path after
the consume write.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-proof-domain-batch-dispatch-fire23"
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
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b")
_BRIDGE_CONTEXT_RE = re.compile(
    r"\b(?:bridge|gateway|crosschain|crossChain|cross[-_ ]?chain|relay|"
    r"relayer|message|dispatch|inbound|outbound|proof|root|commitment|"
    r"receipt|beefy|snowbridge)\b",
    re.IGNORECASE,
)
_BATCH_CONTEXT_RE = re.compile(
    r"\b(?:batch|batches|messages|msgs|commands|routes|payloads)\b|"
    r"\bfor\s*\(",
    re.IGNORECASE,
)
_PROOF_CONTEXT_RE = re.compile(
    r"\b(?:proof|proofs|root|stateRoot|messageRoot|receiptRoot|leaf|"
    r"leafHash|MerkleProof|verifyProof|verifyMessage|verifyRoot|"
    r"verifyCommitment)\b",
    re.IGNORECASE,
)
_DOMAIN_CONTEXT_RE = re.compile(
    r"\b(?:BRIDGE_DOMAIN|DOMAIN|domain|domainId|sourceDomain|srcDomain|"
    r"originDomain|destinationDomain|destDomain|dstDomain|targetDomain|"
    r"sourceChain|srcChain|originChain|destinationChain|destChain|"
    r"dstChain|targetChain|chainId|chainid|block\.chainid|routeId|"
    r"route|channelId|endpointId|eid|address\s*\(\s*this\s*\))\b",
    re.IGNORECASE,
)
_CONSUME_RE = re.compile(
    r"\b(?P<flag>(?:consumed|processed|used|delivered|finalized|executed|"
    r"relayed|dispatched|seen|spent|messageConsumed|receiptConsumed)"
    r"[A-Za-z0-9_]*)\s*\[\s*(?P<key>[^\]]+)\]\s*=\s*true\b|"
    r"\b(?P<setflag>(?:consumed|processed|used|delivered|finalized|executed|"
    r"relayed|dispatched|seen|spent)[A-Za-z0-9_]*)\s*\.\s*(?:set|add)\s*\("
    r"\s*(?P<setkey>[^),]+)",
    re.IGNORECASE | re.DOTALL,
)
_HASH_ASSIGN_RE = re.compile(
    r"\b(?:bytes32\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*"
    r"(?:Key|Id|ID|Hash|Digest|Nonce|Leaf|Receipt))\s*=\s*"
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,900}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_NONREVERTING_DOMAIN_SKIP_RE = re.compile(
    r"\bif\s*\([^)]*(?:source|src|origin|destination|dest|dst|target|"
    r"domain|chain|route|channel|endpoint)[^)]*(?:!=|==)[^)]*\)\s*\{"
    r"[^{}]*(?:continue\s*;|return\s+false\s*;|return\s*;|emit\s+"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\()",
    re.IGNORECASE | re.DOTALL,
)
_NONREVERTING_DISPATCH_FAILURE_RE = re.compile(
    r"(?:"
    r"\bif\s*\(\s*!\s*(?:success|ok|dispatched|delivered|accepted)\s*\)"
    r"\s*\{[^{}]*(?:continue\s*;|return\s+false\s*;|return\s*;|emit\s+"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\()|"
    r"\bcatch\s*(?:\([^)]*\))?\s*\{[^{}]*(?:continue\s*;|"
    r"return\s+false\s*;|return\s*;|success\s*=\s*false|ok\s*=\s*false)"
    r")",
    re.IGNORECASE | re.DOTALL,
)
_ATOMIC_FAILURE_RE = re.compile(
    r"\b(?:require\s*\(\s*(?:success|ok|dispatched|delivered|accepted)\s*[,)]|"
    r"revert\s+[A-Za-z_][A-Za-z0-9_]*\s*\(|catch\s*(?:\([^)]*\))?"
    r"\s*\{[^{}]*\brevert\b|CommandFailed|DispatchFailed|WrongDomain|"
    r"WrongDestination|WrongSource)\b",
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


def _line_for(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _context(fn: FunctionSlice) -> str:
    return f"{fn.name}\n{fn.header}\n{fn.body}"


def _is_bridge_batch_function(fn: FunctionSlice) -> bool:
    text = _context(fn)
    if not _PUBLIC_HEADER_RE.search(fn.header):
        return False
    return (
        bool(_BRIDGE_CONTEXT_RE.search(text))
        and bool(_BATCH_CONTEXT_RE.search(text))
        and bool(_PROOF_CONTEXT_RE.search(text))
        and bool(_DOMAIN_CONTEXT_RE.search(text))
    )


def _assigned_expr_before(body: str, name: str, pos: int) -> str:
    found = ""
    for match in _HASH_ASSIGN_RE.finditer(body[:pos]):
        if match.group("name") == name:
            found = match.group("expr")
    return found


def _weak_consume_key(body: str, match: re.Match[str]) -> bool:
    key = (match.group("key") or match.group("setkey") or "").strip()
    if not key:
        return False
    key_expr = _assigned_expr_before(body, key, match.start())
    if not key_expr:
        key_expr = key

    if _DOMAIN_CONTEXT_RE.search(key_expr):
        return False
    return bool(re.search(r"\b(?:root|proof|leaf|message|msg_|nonce|receipt|payload)\b", key_expr, re.IGNORECASE))


def _nonreverting_gate_after_consume(body: str, consume_pos: int) -> bool:
    tail = body[consume_pos:]
    domain_skip = _NONREVERTING_DOMAIN_SKIP_RE.search(tail)
    dispatch_failure = _NONREVERTING_DISPATCH_FAILURE_RE.search(tail)
    if domain_skip is None and dispatch_failure is None:
        return False
    atomic = _ATOMIC_FAILURE_RE.search(tail)
    if atomic is None:
        return True
    first_nonreverting = min(
        match.start()
        for match in (domain_skip, dispatch_failure)
        if match is not None
    )
    return first_nonreverting < atomic.start()


def _early_consumption(fn: FunctionSlice) -> tuple[re.Match[str], str] | None:
    for match in _CONSUME_RE.finditer(fn.body):
        if not _weak_consume_key(fn.body, match):
            continue
        if not _nonreverting_gate_after_consume(fn.body, match.end()):
            continue

        tail = fn.body[match.end():]
        if _NONREVERTING_DOMAIN_SKIP_RE.search(tail) and _NONREVERTING_DISPATCH_FAILURE_RE.search(tail):
            return match, "domain skip and dispatch failure continue after consume"
        if _NONREVERTING_DOMAIN_SKIP_RE.search(tail):
            return match, "domain skip continues after consume"
        return match, "dispatch failure continues after consume"
    return None


def _finding(file_path: str, line: int, function: str, branch: str) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            f"{branch} in bridge proof-domain batch dispatch path. "
            "A weak consumed key is written before the cross-domain message "
            "is atomically proven and dispatched. Candidate evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _is_bridge_batch_function(fn):
            continue
        early = _early_consumption(fn)
        if early is None:
            continue
        match, branch = early
        findings.append(_finding(file_path, _line_for(fn, match), fn.name, branch))
    return findings
