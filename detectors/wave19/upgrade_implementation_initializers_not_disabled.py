"""
upgrade-implementation-initializers-not-disabled — Wave-5 W5-B3 detector.

Weak-class lift: the catch-rate backtest scored `upgradeability` at 55%
recall - the weakest class in the library. The existing detectors
(`missing-access-control-on-authorizeupgrade`,
`phantom_initialization_hunter`) cover the upgrade authorisation and the
proxy-constructor variants; this detector targets the UNINITIALIZED
IMPLEMENTATION shape.

A UUPS/Transparent upgradeable contract uses an `initialize()` function
(the `initializer` modifier) instead of a constructor. If the
implementation contract's constructor does NOT call
`_disableInitializers()` (OZ >=4.3.2) - or set the legacy
`_initialized = true` sentinel - then ANYONE can call `initialize()`
directly on the implementation, take ownership of the implementation,
and (for UUPS) call `upgradeTo` -> `selfdestruct` / arbitrary delegatecall
to brick or hijack the logic contract.

Pattern (regex-API `scan()`, stdlib only):
    1. Contract is upgradeable-shaped: it inherits an `*Upgradeable` base
       OR defines a function with the `initializer` /
       `reinitializer(` modifier.
    2. NEGATIVE PRECONDITION: no `constructor` body calls
       `_disableInitializers()` and no constructor sets an
       `_initialized`/`_initializing` sentinel. A contract with NO
       constructor at all also fails this (default constructor cannot
       disable initializers).

If (1) AND (2) -> flag the contract. High.

Sibling: `detectors/wave17/phantom_initialization_hunter_constructor_in_proxy_implementation`
covers a constructor PRESENT in a proxy implementation; this detector
covers the inverse - the `_disableInitializers()` call ABSENT.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "upgrade-implementation-initializers-not-disabled"


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
    r"\bcontract\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b(?P<inherit>[^{]*)\{"
)
_INITIALIZER_MOD_RE = re.compile(r"\b(?:initializer|reinitializer\s*\()\b")
_DISABLE_RE = re.compile(r"_disableInitializers\s*\(")
_LEGACY_SENTINEL_RE = re.compile(
    r"_initialized\s*=\s*(?:true|type\s*\(\s*uint8\s*\)\.max|\d+)"
)
_CONSTRUCTOR_RE = re.compile(r"\bconstructor\s*\(")


def _contract_bodies(source: str):
    out = []
    for m in _CONTRACT_RE.finditer(source):
        name = m.group("name")
        inherit = m.group("inherit")
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
        line = source.count("\n", 0, m.start()) + 1
        out.append((name, inherit, body, line))
    return out


def _find_block(source: str, open_idx: int) -> str:
    """Given the index of an opening brace, return the balanced block text."""
    depth = 1
    k = open_idx + 1
    while k < len(source) and depth > 0:
        c = source[k]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        k += 1
    return source[open_idx + 1:k - 1]


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    source = _strip_comments(source)
    findings: List[Finding] = []
    if "Upgradeable" not in source and "initializer" not in source:
        return findings

    for name, inherit, body, line in _contract_bodies(source):
        is_upgradeable = (
            "Upgradeable" in inherit or _INITIALIZER_MOD_RE.search(body) is not None
        )
        if not is_upgradeable:
            continue
        # interfaces / abstract-with-no-initializer are not implementations
        if "interface " in source[:source.find(name)][-40:]:
            continue

        # gather constructor bodies in this contract
        disabled = False
        cm = _CONSTRUCTOR_RE.search(body)
        while cm:
            # locate the constructor's opening brace
            j = cm.end()
            depth_paren = 1
            while j < len(body) and depth_paren > 0:
                if body[j] == "(":
                    depth_paren += 1
                elif body[j] == ")":
                    depth_paren -= 1
                j += 1
            ob = body.find("{", j)
            if ob < 0:
                break
            ctor_body = _find_block(body, ob)
            if _DISABLE_RE.search(ctor_body) or _LEGACY_SENTINEL_RE.search(ctor_body):
                disabled = True
                break
            cm = _CONSTRUCTOR_RE.search(body, j)

        if disabled:
            continue

        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=line,
                severity="High",
                function=name,
                message=(
                    f"Upgradeable contract `{name}` defines an `initializer` "
                    "function but its constructor does not call "
                    "`_disableInitializers()`. Anyone can call `initialize()` "
                    "directly on the deployed implementation, seize ownership "
                    "of the logic contract, and (UUPS) `upgradeTo` an attacker "
                    "implementation or `selfdestruct` it. Add "
                    "`constructor() { _disableInitializers(); }`."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME"]
