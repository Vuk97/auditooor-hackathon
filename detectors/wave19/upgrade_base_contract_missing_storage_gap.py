"""
upgrade-base-contract-missing-storage-gap — Wave-5 W5-B3 detector.

Weak-class lift: `upgradeability` recall 55% (weakest class). A wave18
Slither detector `upgradeable_missing_storage_gap.py` already exists; this
is the regex-API complement so the check still fires on hosts without
solc and so it can be backtested by the stdlib-only catch-rate harness.

An upgradeable BASE contract (one inherited by other upgradeable
contracts, e.g. an abstract `*Upgradeable` mix-in) that declares its own
mutable storage variables MUST reserve a `uint256[N] __gap;` slot range.
Without the gap, appending a variable to the base in a later version
shifts every storage slot of the child contract -> silent storage
collision / corruption on upgrade.

Pattern (regex-API `scan()`, stdlib only):
    1. Contract is an upgradeable base: `abstract contract` whose name or
       inheritance list contains `Upgradeable`, OR a contract that
       inherits `Initializable`/`*Upgradeable` AND is itself inherited
       (heuristic: name ends in `Upgradeable` / `Base` / `Storage`).
    2. The contract declares at least one mutable (non-constant,
       non-immutable) state variable.
    3. NEGATIVE PRECONDITION: no `__gap` array declaration
       (`uint256[<N>] ... __gap` or `_gap`).

If (1) AND (2) AND (3) -> flag. Medium.

Sibling: `detectors/wave18/upgradeable_missing_storage_gap.py` (Slither
AST). Same pattern, regex-API surface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "upgrade-base-contract-missing-storage-gap"


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


_CONTRACT_RE = re.compile(
    r"\b(?P<abstract>abstract\s+)?contract\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\b(?P<inherit>[^{]*)\{"
)
_GAP_RE = re.compile(r"\buint256\s*\[\s*\d*\s*\]\s*(?:private\s+|internal\s+)?__?gap\b")
# a mutable storage var: a type + name + `;`, excluding constant/immutable,
# excluding function-local (we only scan the contract-level region).
_STATE_VAR_RE = re.compile(
    r"^\s*(?:mapping\s*\(|address|uint\d*|int\d*|bool|bytes\d*|string)\b"
    r"(?![^;{]*\b(?:constant|immutable)\b)"
    r"[^;{}()]*;",
    re.MULTILINE,
)
_UPGRADEABLE_HINT_RE = re.compile(r"Upgradeable|Initializable")


def _contract_top_level_region(body: str) -> str:
    """Return body text with nested {...} blocks (functions) blanked out so
    only contract-level declarations remain."""
    out = []
    depth = 0
    for c in body:
        if c == "{":
            depth += 1
            out.append(" ")
        elif c == "}":
            depth = max(0, depth - 1)
            out.append(" ")
        else:
            out.append(c if depth == 0 else " ")
    return "".join(out)


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    source = _strip_comments(source)
    findings: List[Finding] = []
    if not _UPGRADEABLE_HINT_RE.search(source):
        return findings

    for m in _CONTRACT_RE.finditer(source):
        name = m.group("name")
        inherit = m.group("inherit")
        is_abstract = bool(m.group("abstract"))
        brace = m.end() - 1
        depth = 1
        k = brace + 1
        while k < len(source) and depth > 0:
            c = source[k]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            k += 1
        body = source[brace + 1:k - 1]

        # (1) upgradeable base heuristic
        looks_upgradeable = bool(_UPGRADEABLE_HINT_RE.search(inherit) or
                                 _UPGRADEABLE_HINT_RE.search(name))
        is_base = is_abstract or re.search(r"(?:Upgradeable|Base|Storage)$", name)
        if not (looks_upgradeable and is_base):
            continue

        top = _contract_top_level_region(body)
        # (2) has a mutable state var
        if not _STATE_VAR_RE.search(top):
            continue
        # (3) NEGATIVE PRECONDITION: __gap present
        if _GAP_RE.search(top):
            continue

        line = source.count("\n", 0, m.start()) + 1
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=line,
                severity="Medium",
                function=name,
                message=(
                    f"Upgradeable base contract `{name}` declares mutable "
                    "storage but reserves no `uint256[N] __gap;` slot range. "
                    "Appending a variable to this base in a future version "
                    "shifts every inheriting child's storage slots, causing a "
                    "silent storage collision on upgrade. Add a `__gap` array."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME"]
