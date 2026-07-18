"""
v4-hook-take-before-pricing-state-mutation — Cantina #29 detector.

Detects the Uniswap-v4 hook anti-pattern where, inside a function reachable
from `IUnlockCallback.unlockCallback`, the contract calls
`poolManager.take(...)` (native or user-recipient) BEFORE updating
pricing-relevant storage (`reserves`, `_reserves`, `balances`, etc.) — or
calls `Address.sendValue` / low-level `.call{value:}` to a user-controlled
recipient before the same storage update.

Because v4 PoolManager exposes ALL primitives under `onlyWhenUnlocked` for
the duration of the unlock window, the receiver can call back into
`PoolManager.swap()` directly (no nested unlock required) and trade
against stale `reserves[]`. This is the "must reenter through me" mental
model trap codified as L28-A in
`docs/REVERT_GAP_ANALYSIS_2026-05-08.md`.

Module exposes a regex-based `scan(source: str, file_path: str)` API that
returns a list of `Finding` dataclasses. Stdlib-only, no Slither/AST
dependency, so it is callable from `tools/run-fast-detectors.py`-style
runners and from unit tests on raw `.sol` text.

Severity preset: High when (native take or sendValue) AND post-take
mutation of `reserves`-shaped storage is observed.

Spec source: `docs/REVERT_GAP_ANALYSIS_2026-05-08.md` § "A. v4_hook_take_before_pricing_state_mutation".
DO NOT EDIT BY HAND without updating the spec doc.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "v4-hook-take-before-pricing-state-mutation"
DETECTOR_SEVERITY_DEFAULT = "High"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


# Regexes (compiled once).
_FN_HEADER_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
)
_TAKE_RE = re.compile(
    r"\b(?:poolManager|_poolManager|manager)\s*\.\s*take\s*\(",
)
_SENDVALUE_RE = re.compile(
    r"\bAddress\.sendValue\s*\(|\.call\s*\{\s*value\s*:",
)
# pricing-relevant storage write (assignment or +=/-=) on reserve-like
# names.
_RESERVE_WRITE_RE = re.compile(
    r"\b(?:reserves|_reserves|balances|_balances|liquidity|_liquidity)"
    r"\s*(?:\[[^\]]*\])?\s*[\+\-]?=",
)
# Heuristic: function is reachable from unlockCallback if it is named
# unlockCallback OR has a name starting with `_handle` and the file
# contains an `unlockCallback` dispatcher referencing that handler. We
# detect the file-level cue and treat all `_handle*` private fns as
# unlock-reachable.
_UNLOCK_CALLBACK_PRESENT_RE = re.compile(
    r"\bfunction\s+unlockCallback\s*\(",
)
_HANDLER_NAME_RE = re.compile(r"^_handle[A-Z][A-Za-z0-9_]*$")


def _split_functions(source: str) -> List[tuple]:
    """
    Returns a list of (fn_name, body_text, body_start_line, fn_start_offset).

    Splits a Solidity source into function bodies using brace-depth
    counting. Resilient to nested braces (loops, if-blocks). Skips
    abstract / interface declarations (no body).
    """
    out = []
    pos = 0
    while True:
        m = _FN_HEADER_RE.search(source, pos)
        if not m:
            break
        name = m.group("name")
        # find the opening brace of the body, if any
        i = m.end()
        depth_paren = 1
        # consume the parameter / modifier / returns clause to find {
        while i < len(source) and depth_paren > 0:
            c = source[i]
            if c == "(":
                depth_paren += 1
            elif c == ")":
                depth_paren -= 1
            i += 1
        # now skip any modifiers / returns(...) / `;` (no-body)
        # advance to first `{` or `;` (whichever first)
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
        # brace-walk to body end
        depth = 1
        k = body_start + 1
        while k < len(source) and depth > 0:
            c = source[k]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            k += 1
        body_end = k
        body_text = source[body_start + 1:body_end - 1]
        body_start_line = source.count("\n", 0, body_start + 1) + 1
        out.append((name, body_text, body_start_line, m.start()))
        pos = body_end
    return out


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    """
    Run the detector against raw Solidity source. Returns Finding list
    (empty when clean).
    """
    findings: List[Finding] = []
    # Gate: file references the v4 PoolManager / unlock surface, OR
    # defines `_handle*` callback handlers that are reachable from a
    # peer file's `unlockCallback`. We accept any of those.
    has_unlock_cb = bool(_UNLOCK_CALLBACK_PRESENT_RE.search(source))
    has_iunlock_import = "IUnlockCallback" in source
    has_handle_fn = bool(re.search(r"\bfunction\s+_handle[A-Z]", source))
    has_poolmanager = "poolManager" in source or "PoolManager" in source
    if not (has_unlock_cb or has_iunlock_import or (has_handle_fn and has_poolmanager)):
        return findings

    for fn_name, body, body_line, _ in _split_functions(source):
        # only consider unlock-reachable handlers (heuristic).
        if fn_name != "unlockCallback" and not _HANDLER_NAME_RE.match(fn_name):
            continue
        # find positions of takes / sendValue and reserves writes
        take_positions = [
            m.start() for m in _TAKE_RE.finditer(body)
        ]
        send_positions = [
            m.start() for m in _SENDVALUE_RE.finditer(body)
        ]
        write_positions = [
            m.start() for m in _RESERVE_WRITE_RE.finditer(body)
        ]
        if not (take_positions or send_positions):
            continue
        if not write_positions:
            continue
        # Fire when ANY take/sendValue happens BEFORE any reserves write.
        first_external_payout = min(take_positions + send_positions)
        max_write_after = max(write_positions) if write_positions else -1
        if first_external_payout < max_write_after:
            # determine line of the first external payout
            line_in_body = body.count("\n", 0, first_external_payout)
            line = body_line + line_in_body
            kind = "take" if take_positions and first_external_payout in take_positions else "sendValue"
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn_name,
                    message=(
                        f"`{kind}(...)` to recipient happens before pricing-state "
                        f"mutation in unlock-reachable handler `{fn_name}`. Recipient "
                        "can call `PoolManager.swap()` under `onlyWhenUnlocked` and "
                        "trade against stale reserves (Cantina #29 / L28-A)."
                    ),
                )
            )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
