"""
sig-eip712-domain-missing-chainid — Wave-5 W5-B3 detector.

Weak-class lift: the catch-rate backtest scored `signature-replay` at 60%
recall. The existing `eip712_domain_separator_used_without_chainid` fixture
is a known MISS variant. This detector targets the hand-rolled EIP-712
DOMAIN_SEPARATOR construction that omits `block.chainid` (or `chainId`)
from the hashed domain struct.

EIP-712 domain typehash is canonically
`EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)`.
A domain separator built by `keccak256(abi.encode(typehash, name, version,
verifyingContract))` with NO chainId field makes a signature minted on
chain A replayable verbatim on chain B (and on a post-fork chain).

Pattern (regex-API `scan()`, stdlib only):
    1. The contract builds a domain separator: an `abi.encode(`/`abi.encodePacked(`
       expression assigned into a variable whose name contains
       `domain`+`sep` (case-insensitive), OR an `EIP712Domain(` typehash
       string literal is present.
    2. NEGATIVE PRECONDITION 1: `block.chainid` / `chainid()` / a
       `chainId` identifier does NOT appear anywhere in the domain
       construction window.
    3. NEGATIVE PRECONDITION 2: contract does not inherit OZ
       `EIP712` / `EIP712Upgradeable` and does not define
       `_domainSeparatorV4` (those re-derive with chainid - safe).

If (1) AND (2) AND (3) -> flag. High.

Sibling shape: `detectors/wave18/cached_domain_separator_fork_stale.py`
targets the CACHED-immutable fork-stale variant; this detector targets the
chainId-OMITTED-entirely variant. Complementary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "sig-eip712-domain-missing-chainid"


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


_DOMAIN_TYPEHASH_RE = re.compile(r"EIP712Domain\s*\(", re.IGNORECASE)
_DOMAIN_VAR_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*[Dd]omain[A-Za-z0-9_]*[Ss]ep[A-Za-z0-9_]*)\s*=\s*"
    r"keccak256\s*\(\s*abi\.encode(?:Packed)?\s*\(",
)
_CHAINID_RE = re.compile(r"\b(?:block\.chainid|chainid\s*\(\s*\)|chainId|CHAIN_ID|_chainId)\b")
_OZ_EIP712_RE = re.compile(r"\bis\b[^{;]*\bEIP712(?:Upgradeable)?\b")
_DOMAIN_V4_RE = re.compile(r"\b_domainSeparatorV4\b")


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    source = _strip_comments(source)
    findings: List[Finding] = []

    # NEGATIVE PRECONDITION 2: OZ EIP712 base or _domainSeparatorV4 helper.
    if _OZ_EIP712_RE.search(source) or _DOMAIN_V4_RE.search(source):
        return findings

    candidates = []
    for m in _DOMAIN_VAR_ASSIGN_RE.finditer(source):
        candidates.append((m.start(), m.group(1)))
    if not candidates and _DOMAIN_TYPEHASH_RE.search(source):
        # typehash-string-literal form: still a domain construction.
        tm = _DOMAIN_TYPEHASH_RE.search(source)
        candidates.append((tm.start(), "EIP712Domain typehash"))

    if not candidates:
        return findings

    for start, label in candidates:
        # window: the encode expression (next 400 chars) plus the typehash
        # string definition area (prev 400 chars) - chainId can appear in
        # either the typehash string or the encoded value list.
        window = source[max(0, start - 400): start + 400]
        if _CHAINID_RE.search(window):
            continue
        line = source.count("\n", 0, start) + 1
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=line,
                severity="High",
                function=None,
                message=(
                    f"EIP-712 domain construction (`{label}`) omits "
                    "`block.chainid`. A signature minted on one chain is "
                    "replayable verbatim on every other chain (and on a "
                    "post-fork chain) where the contract is deployed. Include "
                    "`chainId` in the EIP712Domain typehash and the encoded "
                    "value, or inherit OpenZeppelin `EIP712`."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME"]
