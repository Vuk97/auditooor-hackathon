"""
sig-signed-action-missing-deadline — Wave-5 W5-B3 detector.

Weak-class lift: `signature-replay` recall 60%. Even when a signed action
has nonce protection, a signature with NO deadline / expiry is a
long-lived bearer credential: an off-chain-leaked or never-submitted
signature stays valid indefinitely, and a stale signed price/intent can
be replayed at an attacker-chosen later block.

Pattern (regex-API `scan()`, stdlib only):
    1. Function body recovers a signer (`ecrecover`/`ECDSA.recover`/`.recover(`)
       AND the function is state-mutating.
    2. NEGATIVE PRECONDITION: the body has NO deadline/expiry enforcement -
       no `require(... deadline ...)`, no `block.timestamp <= deadline`,
       no `expiry`/`validUntil`/`deadline` compared against
       `block.timestamp`, no `> block.timestamp` / `< deadline` guard.
    3. The recovered digest hashes a `deadline`-less struct: the
       function's signature parameter list does not include a
       `deadline`/`expiry`/`validUntil`/`validBefore` parameter either
       (so the omission is structural, not just an unchecked param).

If (1) AND (2) AND (3) -> flag. Medium.

Sibling: complements `sig-recover-without-nonce-or-consumed-mark` (nonce
axis) and `sig-eip712-domain-missing-chainid` (chain axis). Together the
three cover the nonce / chainId / deadline replay triad.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "sig-signed-action-missing-deadline"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def _strip_comments(src: str) -> str:
    """Remove // and /* */ comments so detector regexes never match prose."""
    return _LINE_COMMENT_RE.sub("", _BLOCK_COMMENT_RE.sub("", src))


_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_RECOVER_RE = re.compile(r"\b(?:ecrecover|ECDSA\.recover|\.recover)\s*\(")
_DEADLINE_TOKEN_RE = re.compile(
    r"\b(?:deadline|expiry|validUntil|validBefore|expiration|expiresAt|notAfter)\b",
    re.IGNORECASE,
)
_TIMESTAMP_GUARD_RE = re.compile(
    r"block\.timestamp\s*(?:<=?|>=?)|"
    r"(?:<=?|>=?)\s*block\.timestamp",
)


def _split_functions(source: str) -> List[tuple]:
    out = []
    pos = 0
    while True:
        m = _FN_HEADER_RE.search(source, pos)
        if not m:
            break
        name = m.group("name")
        i = m.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            c = source[i]
            if c == "(":
                depth_paren += 1
            elif c == ")":
                depth_paren -= 1
            i += 1
        params = source[m.end():i - 1]
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
        sig_region = source[i:body_start]
        depth = 1
        k = body_start + 1
        while k < len(source) and depth > 0:
            c = source[k]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            k += 1
        body_text = source[body_start + 1:k - 1]
        body_start_line = source.count("\n", 0, body_start + 1) + 1
        out.append((name, params, sig_region, body_text, body_start_line))
        pos = k
    return out


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    source = _strip_comments(source)
    findings: List[Finding] = []
    if "recover" not in source and "ecrecover" not in source:
        return findings

    for fn_name, params, sig_region, body, body_line in _split_functions(source):
        rm = _RECOVER_RE.search(body)
        if not rm:
            continue
        if re.search(r"\b(?:view|pure)\b", sig_region):
            continue
        # deadline token present anywhere in params or body -> assume handled
        if _DEADLINE_TOKEN_RE.search(params) or _DEADLINE_TOKEN_RE.search(body):
            continue
        # a bare timestamp comparison can serve as an inline expiry guard
        if _TIMESTAMP_GUARD_RE.search(body):
            continue
        line_in_body = body.count("\n", 0, rm.start())
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=body_line + line_in_body,
                severity="Medium",
                function=fn_name,
                message=(
                    f"`{fn_name}` acts on a recovered signature with NO "
                    "deadline/expiry: neither a `deadline`-class parameter nor "
                    "a `block.timestamp` guard is present. The signature is a "
                    "perpetual bearer credential - a leaked or stale signature "
                    "is replayable at an attacker-chosen later block. Add a "
                    "signed `deadline` field checked against `block.timestamp`."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME"]
