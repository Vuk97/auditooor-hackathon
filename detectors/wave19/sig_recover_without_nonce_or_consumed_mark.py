"""
sig-recover-without-nonce-or-consumed-mark — Wave-5 W5-B3 detector.

Weak-class lift: `signature-replay` recall 60%. The
`batched_ecrecover_with_no_per_signer_tracking_replay_risk` fixture is a
known MISS. This detector targets the canonical single-signature replay
shape: a function recovers a signer with `ecrecover` / `ECDSA.recover` /
`.recover(` and acts on the result, but never marks the signature /
digest / nonce as consumed - so the same signature is replayable forever.

Pattern (regex-API `scan()`, stdlib only):
    1. Function body calls `ecrecover(` or `ECDSA.recover(` or `.recover(`.
    2. NEGATIVE PRECONDITION - replay protection present. Skip if the body
       contains ANY of:
       - a nonce increment: `nonce++`, `nonce += 1`, `++nonce`,
         `_useNonce(`, `nonces[...]++`.
       - a consumed-mapping write: `<map>[<digest|sig|hash>] = true` or
         `consumed[...]` / `usedSignatures[...]` / `executed[...]` write.
       - a deadline AND nonce reference together (Permit-style).
       - an `_useUnorderedNonce` / `invalidateNonces` / `bitmap` call.
    3. The function is state-mutating (not `view`/`pure`) - a replay only
       matters if the recovered signer authorises a side effect.

If (1) AND (2) AND (3) -> flag. High.

Sibling: this is the regex-API complement to the corpus fixture
`batched_ecrecover_with_no_per_signer_tracking_replay_risk` and to
`detectors/wave18/forwarder_nonce_on_revert.py`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "sig-recover-without-nonce-or-consumed-mark"


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


_FN_HEADER_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_RECOVER_RE = re.compile(r"\b(?:ecrecover|ECDSA\.recover|\.recover)\s*\(")
_VIEW_PURE_RE = re.compile(r"\)\s*(?:external|public|internal|private)?[^{;]*\b(?:view|pure)\b")

_NONCE_BUMP_RE = re.compile(
    r"(?:\bnonce\w*\s*(?:\+\+|\+=)|\+\+\s*nonce\w*|"
    r"nonces?\s*\[[^\]]+\]\s*(?:\+\+|\+=)|_useNonce\s*\(|"
    r"_useUnorderedNonce\s*\(|invalidateUnorderedNonces\s*\(|"
    r"_useCheckedNonce\s*\()",
    re.IGNORECASE,
)
_CONSUMED_WRITE_RE = re.compile(
    r"(?:consumed|usedSig\w*|usedHash\w*|executed|seenDigest\w*|"
    r"isUsed|signatureUsed|claimed|processed)\s*\[[^\]]+\]\s*=\s*true",
    re.IGNORECASE,
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
        # signature region between `)` and `{`
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
        out.append((name, sig_region, body_text, body_start_line))
        pos = k
    return out


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    source = _strip_comments(source)
    findings: List[Finding] = []
    if "recover" not in source and "ecrecover" not in source:
        return findings

    for fn_name, sig_region, body, body_line in _split_functions(source):
        rm = _RECOVER_RE.search(body)
        if not rm:
            continue
        # state-mutating only
        if re.search(r"\b(?:view|pure)\b", sig_region):
            continue
        # NEGATIVE PRECONDITION: replay protection in body.
        if _NONCE_BUMP_RE.search(body) or _CONSUMED_WRITE_RE.search(body):
            continue
        line_in_body = body.count("\n", 0, rm.start())
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=body_line + line_in_body,
                severity="High",
                function=fn_name,
                message=(
                    f"`{fn_name}` recovers a signer from a signature and "
                    "performs a state change, but never marks the signature, "
                    "digest, or nonce as consumed. The same signature is "
                    "replayable until the contract is killed. Add a nonce "
                    "bump or a `consumed[digest] = true` guard."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME"]
