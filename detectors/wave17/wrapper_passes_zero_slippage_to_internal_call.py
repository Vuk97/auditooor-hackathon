"""
wrapper-passes-zero-slippage-to-internal-call — periphery anchoring-trap
detector (Cantina Revert #15 — and the general shape).

Detects the periphery / wrapper / zap anti-pattern where a function
constructs a fresh ZERO `uint256[]` (or empty / sentinel-zero) array
locally and passes it as the slippage / minimum-output parameter on
an internal call to a sibling DEX/AMM/lending primitive
(`addLiquidity`, `removeLiquidity`, `swap`, `deposit`, `mint`,
`redeem`, `withdraw`), AND/OR passes a zero scalar `minShares` /
`minOut` / `minAmount` literal `0` to the same call.

The outer-only `_minShares` / `slippage` check on the wrapper itself
is INSUFFICIENT because the inner primitive performs no per-leg
slippage check, and a sandwicher can grief the imbalance leg
(arbitrary asymmetric extraction) while the outer `minShares` clamp
remains satisfied. The general shape is universal: any periphery
that "splits" a user trade into multiple internal calls and only
clamps the aggregate output is vulnerable to per-leg manipulation.

Module exposes a regex-based `scan(source: str, file_path: str)` API.
Stdlib-only — no Slither/AST dependency. Mirrors the wave17 style of
`v4_hook_take_before_pricing_state_mutation.py`.

Severity preset: Medium when (zero-array OR zero-literal min) is
passed to a primitive call shape AND the calling contract is a
periphery/wrapper-flavored contract (heuristic: file path contains
`periphery|zap|wrapper|router|helper`, OR contract name endswith
`ZapIn|ZapOut|Router|Helper|Periphery|Wrapper`, OR the calling
function is `external|public payable` user-entry-shaped).

Spec source: `docs/REVERT_GAP_ANALYSIS_2026-05-08.md` § Finding #15.
DO NOT EDIT BY HAND without updating the spec doc.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "wrapper-passes-zero-slippage-to-internal-call"
DETECTOR_SEVERITY_DEFAULT = "Medium"


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

# Contract / interface header (used for periphery-name heuristic).
_CONTRACT_NAME_RE = re.compile(
    r"\b(?:contract|library|abstract\s+contract)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
)

# A fresh local zero `uint256[]` allocation, plus its variable name.
# Matches both `uint256[] memory minAmounts = new uint256[](len);` and
# `uint256[] memory minOutputs = new uint256[](_currencies.length);`.
_ZERO_ARRAY_DECL_RE = re.compile(
    r"\buint256\s*\[\s*\]\s+memory\s+(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+uint256\s*\[\s*\]\s*\(",
)

# Primitive-call shapes we care about (sibling DEX/AMM/lending entrypoints).
# Loose match: any `<receiver>.<method>(...)` whose method matches a
# known primitive verb. We then inspect the argument list textually for
# the zero-slippage signature.
_PRIMITIVE_METHODS = (
    "addLiquidity",
    "removeLiquidity",
    "swap",
    "exactInput",
    "exactOutput",
    "exactInputSingle",
    "exactOutputSingle",
    "deposit",
    "mint",
    "redeem",
    "withdraw",
    "join",
    "exit",
    "zapIn",
    "zapOut",
)
_PRIMITIVE_CALL_RE = re.compile(
    r"\b(?P<receiver>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\.\s*(?P<method>"
    + "|".join(_PRIMITIVE_METHODS)
    + r")\s*"
    r"(?:\{[^}]*\})?\s*"  # optional `{value: x}` modifier
    r"\(",
)

# Periphery-name heuristic.
_PERIPHERY_PATH_RE = re.compile(r"periphery|zap|wrapper|router|helper", re.IGNORECASE)
_PERIPHERY_CONTRACT_NAME_RE = re.compile(
    r"(?:ZapIn|ZapOut|Router|Helper|Periphery|Wrapper)\b",
)


def _argspan(source: str, paren_open: int) -> Optional[str]:
    """
    Return the argument-list substring (between matched parens) starting
    at the `(` index `paren_open`, or None if unbalanced.
    """
    if paren_open >= len(source) or source[paren_open] != "(":
        return None
    depth = 1
    i = paren_open + 1
    while i < len(source) and depth > 0:
        c = source[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if depth == 0:
            return source[paren_open + 1:i]
        i += 1
    return None


def _split_top_level_args(arg_text: str) -> List[str]:
    """
    Split a comma-separated argument list, respecting nested parens /
    brackets. Returns trimmed argument substrings.
    """
    parts: List[str] = []
    depth = 0
    cur = []
    for c in arg_text:
        if c in "([{":
            depth += 1
            cur.append(c)
        elif c in ")]}":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


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
        body_end = k
        body_text = source[body_start + 1:body_end - 1]
        body_start_line = source.count("\n", 0, body_start + 1) + 1
        out.append((name, body_text, body_start_line, m.start()))
        pos = body_end
    return out


def _is_periphery_file(source: str, file_path: str) -> bool:
    if _PERIPHERY_PATH_RE.search(file_path):
        return True
    for m in _CONTRACT_NAME_RE.finditer(source):
        if _PERIPHERY_CONTRACT_NAME_RE.search(m.group("name")):
            return True
    return False


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    findings: List[Finding] = []
    if not _is_periphery_file(source, file_path):
        # If neither path nor contract-name suggests periphery, the
        # detector still inspects but raises severity bar. We continue
        # but only flag findings whose enclosing function is `external`
        # or `public`.
        periphery = False
    else:
        periphery = True

    fns = _split_functions(source)
    for fn_name, body, body_line, _ in fns:
        # collect zero-array declarations (var-name -> body offset)
        zero_array_vars: dict[str, int] = {}
        for zm in _ZERO_ARRAY_DECL_RE.finditer(body):
            var = zm.group("var")
            # Guardrail: if the variable is subsequently written to
            # (e.g. `minAmounts[i] = _userMin[i];`), it is no longer a
            # zero-array — drop it from the trigger set.
            written_re = re.compile(
                r"\b" + re.escape(var) + r"\s*\[\s*[^\]]+\s*\]\s*="
            )
            if written_re.search(body[zm.end():]):
                continue
            zero_array_vars[var] = zm.start()

        # iterate each primitive call inside this function
        for cm in _PRIMITIVE_CALL_RE.finditer(body):
            method = cm.group("method")
            paren_idx = cm.end() - 1  # the `(` position in body
            args_str = _argspan(body, paren_idx)
            if args_str is None:
                continue
            # Identify if any arg is one of the zero-array vars OR is
            # itself a fresh `new uint256[](...)` expression OR is the
            # literal `0` that lands in a min-slippage position.
            args = _split_top_level_args(args_str)
            if not args:
                continue

            triggers: List[str] = []

            # Check each arg for known signatures.
            for ai, arg in enumerate(args):
                # zero-array variable reuse
                for zv in zero_array_vars:
                    if re.search(r"\b" + re.escape(zv) + r"\b", arg):
                        triggers.append(f"arg[{ai}] reuses zero-array `{zv}`")
                        break
                # inline `new uint256[](len)` allocation as the arg
                if re.search(r"\bnew\s+uint256\s*\[\s*\]\s*\(", arg):
                    triggers.append(f"arg[{ai}] inline-allocates a zero `uint256[]`")
                # bare literal zero in a min-slippage-shaped arg
                # position (last arg or arg name suggests min)
                if arg.strip() == "0":
                    is_last = ai == len(args) - 1
                    if is_last:
                        triggers.append(f"arg[{ai}] passes literal `0` as last (min-slippage-shaped) param")

            if not triggers:
                continue

            # Periphery / external-entry guard: if the file is not
            # periphery-flavored, only fire when the caller is an
            # external/public entrypoint. We approximate with the
            # function-header text near the function start.
            if not periphery:
                # find the function-header in source (look 200 chars
                # back from body in original source).
                # Simpler: scan the function header line text in `source`.
                hdr_match = re.search(
                    r"function\s+" + re.escape(fn_name) + r"\b[^{;]*",
                    source,
                )
                if not hdr_match or not re.search(r"\b(?:external|public)\b", hdr_match.group(0)):
                    continue

            # Determine fire line in the original source.
            line_in_body = body.count("\n", 0, cm.start())
            line = body_line + line_in_body
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn_name,
                    message=(
                        f"Periphery `{fn_name}` calls `{method}(...)` with a "
                        f"zero-slippage parameter ({'; '.join(triggers)}). "
                        "Outer-only aggregate min-clamp is insufficient; the "
                        "inner primitive performs no per-leg slippage check, "
                        "so a sandwicher can grief the imbalance leg "
                        "(L29-Discovery anchoring-trap; Revert Cantina #15)."
                    ),
                )
            )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
