"""
erc4626-donation-inflation-no-virtual-offset — Wave-5 W5-B3 detector.

Weak-class lift: the detector catch-rate backtest scored the
`erc4626-vault` class at 60% recall. The single existing first-depositor
detector matches only the `if (totalSupply == 0) shares = assets` bootstrap
branch; it misses the broader DONATION/INFLATION shape where the vault has
a function that pushes underlying into the vault accounting WITHOUT minting
shares (a `donate`-style sink, or `totalAssets()` reading a raw
`asset.balanceOf(address(this))`), and the share-conversion math has no
virtual-offset cushion.

Pattern (regex-API `scan()`, stdlib only):
    1. Contract is ERC4626-shaped: defines a `deposit`/`mint` function AND a
       `convertToShares`/`previewDeposit`/share-math expression
       `assets * totalSupply / totalAssets` (or `* supply / `).
    2. There exists a donation sink: a function whose body increments a
       managed-assets state var or whose `totalAssets()` reads
       `balanceOf(address(this))` directly — assets can enter accounting
       without a matching share mint.
    3. NEGATIVE PRECONDITION: no virtual-offset cushion anywhere in the
       contract — no `_decimalsOffset`, no `VIRTUAL_SHARES`/`VIRTUAL_ASSETS`,
       no `+ 1` / `+ 10 **` literal added inside the share-conversion
       expression, no `bootstrap`/`firstDeposit` guard helper.

If (1) AND (2) AND (3) -> flag the conversion function. Medium.

Sibling: `detectors/wave17/erc4626_first_depositor_attack_share_price_manipulation.py`
covers only the `totalSupply == 0` branch and uses Slither's AST. This
detector is the donation/inflation complement and runs without solc.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "erc4626-donation-inflation-no-virtual-offset"


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
_DEPOSIT_FN_RE = re.compile(r"\bfunction\s+(?:deposit|mint)\s*\(")
_SHARE_MATH_RE = re.compile(
    r"\*\s*(?:totalSupply|totalShares|_?totalSupply|supply)\b\s*[\)\s]*/\s*"
    r"(?:totalAssets|totalManagedAssets|managedAssets|_?totalAssets|assetBalance)"
)
_DONATION_SINK_RE = re.compile(
    r"(?:totalManagedAssets|totalAssets|managedAssets|assetBalance|_totalAssets)\s*\+="
)
_RAW_BALANCE_TOTALASSETS_RE = re.compile(
    r"\btotalAssets\s*\([^)]*\)[^{]*\{[^}]*balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)"
)
# safe cushions anywhere in the contract
_VIRTUAL_OFFSET_RE = re.compile(
    r"(?:_decimalsOffset|VIRTUAL_SHARES|VIRTUAL_ASSETS|virtualShares|virtualAssets|"
    r"\bbootstrap[A-Za-z]*|firstDeposit|initialDeposit|_seedVault|DEAD_SHARES)",
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
    if "deposit" not in source and "mint" not in source:
        return findings
    if not _DEPOSIT_FN_RE.search(source):
        return findings

    # NEGATIVE PRECONDITION: any virtual-offset cushion -> contract is safe.
    if _VIRTUAL_OFFSET_RE.search(source):
        return findings

    has_donation_sink = bool(
        _DONATION_SINK_RE.search(source) or _RAW_BALANCE_TOTALASSETS_RE.search(source)
    )
    if not has_donation_sink:
        return findings

    for fn_name, body, body_line in _split_functions(source):
        m = _SHARE_MATH_RE.search(body)
        if not m:
            continue
        # safe if a `+ <literal>` cushion sits inside the same expression
        window = body[max(0, m.start() - 120): m.end() + 120]
        if re.search(r"\+\s*(?:1\b|10\s*\*\*|VIRTUAL|virtual)", window):
            continue
        line_in_body = body.count("\n", 0, m.start())
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=body_line + line_in_body,
                severity="Medium",
                function=fn_name,
                message=(
                    f"`{fn_name}` converts assets->shares via raw "
                    "`assets * totalSupply / totalAssets` while the vault has a "
                    "donation sink (assets enter accounting without a share "
                    "mint) and NO virtual-offset cushion. First/early depositor "
                    "can donate underlying to inflate the exchange rate and "
                    "round a victim's shares to zero (ERC4626 inflation attack)."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME"]
