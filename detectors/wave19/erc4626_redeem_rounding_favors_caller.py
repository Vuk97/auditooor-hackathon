"""
erc4626-redeem-rounding-favors-caller — Wave-5 W5-B3 detector.

Weak-class lift: `erc4626-vault` recall 60%. The existing first-depositor
detector and the donation-inflation sibling cover bootstrap manipulation;
neither catches the ROUNDING-DIRECTION bug where the vault rounds in the
caller's favour on a value-extracting path.

ERC4626 spec rule: deposit/mint must round shares DOWN to the user (and
assets UP from the user); withdraw/redeem must round assets DOWN to the
user (and shares UP from the user). A vault that uses `mulDivUp` /
`ceilDiv` / a `+ denominator - 1` numerator on a `redeem`/`withdraw`
asset-out path, or `mulDivDown` / plain `/` on the share-in path, lets a
caller extract a wei per call and drain the vault over many iterations.

Pattern (regex-API `scan()`, stdlib only):
    1. Function name matches `redeem|withdraw` (asset-OUT path).
    2. Its body contains a round-UP idiom for the asset-out amount:
       `mulDivUp(`, `mulDivRoundingUp(`, `ceilDiv(`, or an explicit
       `(... + <denom> - 1) / <denom>` ceiling expression.
    3. NEGATIVE PRECONDITION: the body does not also carry an explicit
       `Math.Rounding.Floor` / `roundDown` / `mulDivDown` marker on the
       same amount (some libs pass an explicit rounding enum — if a Floor
       marker is present the path is intentionally floored, skip).

If (1) AND (2) AND (3) -> flag. Medium.

Sibling: `detectors/wave17/erc4626_first_depositor_attack_share_price_manipulation.py`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "erc4626-redeem-rounding-favors-caller"


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
_ASSET_OUT_FN_RE = re.compile(r"^(?:redeem|withdraw)", re.IGNORECASE)
_ROUND_UP_RE = re.compile(
    r"\b(?:mulDivUp|mulDivRoundingUp|ceilDiv|divUp|roundUp)\s*\(",
)
_CEIL_EXPR_RE = re.compile(
    r"\(\s*[A-Za-z0-9_.\*\s]+\+\s*[A-Za-z0-9_]+\s*-\s*1\s*\)\s*/",
)
_FLOOR_MARKER_RE = re.compile(
    r"(?:Math\.Rounding\.Floor|Rounding\.Floor|roundDown|mulDivDown|RoundingDown)",
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
        out.append((name, body_text, body_start_line))
        pos = k
    return out


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    source = _strip_comments(source)
    findings: List[Finding] = []
    if "redeem" not in source and "withdraw" not in source:
        return findings

    for fn_name, body, body_line in _split_functions(source):
        if not _ASSET_OUT_FN_RE.match(fn_name):
            continue
        up = _ROUND_UP_RE.search(body) or _CEIL_EXPR_RE.search(body)
        if not up:
            continue
        # explicit Floor marker near the round-up hit -> intentionally floored
        window = body[max(0, up.start() - 100): up.end() + 100]
        if _FLOOR_MARKER_RE.search(window):
            continue
        line_in_body = body.count("\n", 0, up.start())
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=body_line + line_in_body,
                severity="Medium",
                function=fn_name,
                message=(
                    f"`{fn_name}` is an ERC4626 asset-OUT path that rounds the "
                    "amount UP (mulDivUp/ceilDiv/`+denom-1` ceiling). Spec "
                    "requires withdraw/redeem to round assets DOWN to the user; "
                    "rounding up lets a caller extract 1 wei per call and drain "
                    "the vault over many iterations."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME"]
