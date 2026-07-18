"""
v4-settle-without-prior-sync — Cantina #995 detector.

Uniswap-v4's `CurrencyReserves` (sync/settle state) lasts the WHOLE
transaction. A prior same-tx call that synced an ERC20 leaves the
manager in ERC20-settlement mode; a later native `settle{value:}` then
reverts with `NonzeroNativeValue`. Native paths must therefore call
`sync(address(0))` before any native settle, even if the function
itself only handles native ETH internally.

Highest-confidence shape (sibling-branch asymmetry): the function has
both an ERC20 branch (`sync(currency); ... settle()`) and a native
branch (`settle{value:}` only). The team's own ERC20 branch proves they
know sync is required; the native branch missing-protection is a
classic L26 "bug-by-omission anchor".

Spec: `docs/REVERT_GAP_ANALYSIS_2026-05-08.md` § "D".

Severity preset:
  - Medium when sibling-branch asymmetry is detected
  - Low when only an isolated native settle without dominating sync is
    found (no sibling proof).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "v4-settle-without-prior-sync"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


_FN_HEADER_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
)
_NATIVE_SETTLE_RE = re.compile(
    r"\b(?:poolManager|_poolManager|manager)\s*\.\s*settle\s*\{\s*value\s*:",
)
_PLAIN_SETTLE_RE = re.compile(
    r"\b(?:poolManager|_poolManager|manager)\s*\.\s*settle\s*\(",
)
_SYNC_RE = re.compile(
    r"\b(?:poolManager|_poolManager|manager)\s*\.\s*sync\s*\(",
)
# branch detection: balanced if/else block boundaries are too regex-
# unfriendly. Approximation: split body on `else {` and check each
# segment for sync / native settle independently.
_BRANCH_SPLIT_RE = re.compile(r"\belse\s*\{")


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
        out.append((name, body_text, body_start_line, m.start()))
        pos = k
    return out


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    findings: List[Finding] = []
    if "settle" not in source:
        return findings

    for fn_name, body, body_line, _ in _split_functions(source):
        native_hits = list(_NATIVE_SETTLE_RE.finditer(body))
        if not native_hits:
            continue
        # find sync hits and segment branches
        sync_hits = list(_SYNC_RE.finditer(body))
        # for each native settle, check if a sync(address(0)) precedes it
        # in the same branch. If not, decide severity by sibling shape.
        # Branch heuristic: use top-level if/else split.
        for ns in native_hits:
            ns_pos = ns.start()
            preceding_sync = [s for s in sync_hits if s.start() < ns_pos]
            # naive: any sync before is "ok" if `sync(address(0))` /
            # `sync(currency)` where currency is zero. We accept any
            # `sync(...)` call with `address(0)` arg as a safe sync.
            safe_sync = False
            for s in preceding_sync:
                # peek up to next 80 chars for the arg
                snippet = body[s.start():s.start() + 80]
                if re.search(r"sync\s*\(\s*(?:address\s*\(\s*0\s*\)|Currency\.wrap\s*\(\s*address\s*\(\s*0\s*\)\s*\)|CurrencyLibrary\.NATIVE)\s*\)", snippet):
                    safe_sync = True
                    break
            if safe_sync:
                continue
            # sibling-branch asymmetry: does the OTHER branch (i.e. the
            # body region NOT containing the native settle) call sync?
            # Approximation: split on `else {` boundaries.
            sibling_has_sync = False
            split_points = [m.start() for m in _BRANCH_SPLIT_RE.finditer(body)]
            if split_points:
                # determine which segment ns_pos lives in
                bounds = [0] + split_points + [len(body)]
                native_seg = None
                for idx in range(len(bounds) - 1):
                    if bounds[idx] <= ns_pos < bounds[idx + 1]:
                        native_seg = idx
                        break
                for idx in range(len(bounds) - 1):
                    if idx == native_seg:
                        continue
                    seg_text = body[bounds[idx]:bounds[idx + 1]]
                    if _SYNC_RE.search(seg_text):
                        sibling_has_sync = True
                        break
            sev = "Medium" if sibling_has_sync else "Low"
            line_in_body = body.count("\n", 0, ns_pos)
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=body_line + line_in_body,
                    severity=sev,
                    function=fn_name,
                    message=(
                        f"`{fn_name}` calls native `settle{{value:}}` without a "
                        "dominating `sync(address(0))`. "
                        + (
                            "Sibling ERC20 branch DOES call sync — bug-by-"
                            "omission anchor; cross-tx ERC20 sync state can "
                            "make the native settle revert with NonzeroNativeValue "
                            "(Cantina #995 / L28-A primitive #3)."
                            if sibling_has_sync
                            else "No sibling sync evidence; possible cross-tx "
                                 "DoS via stale CurrencyReserves state."
                        )
                    ),
                )
            )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME"]
