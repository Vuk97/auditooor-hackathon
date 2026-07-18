"""
upgrade-authorize-upgrade-unprotected — Wave-5 W5-B3 detector.

Weak-class lift: `upgradeability` recall 55% (weakest class). The corpus
already carries `missing-access-control-on-authorizeupgrade`, but the
Slither-AST variant misses the common shape where `_authorizeUpgrade`
exists with a BODY that has no access-control statement at all (an empty
`{}` body, or a body that only has comments / an unrelated statement).

In OZ UUPS, `UUPSUpgradeable` calls the override hook
`_authorizeUpgrade(address)` from `upgradeToAndCall`. The override is the
ONLY thing standing between an arbitrary caller and a full logic-contract
swap. A hook implemented as `function _authorizeUpgrade(address) internal
override {}` (empty) makes the proxy permissionlessly upgradeable -> total
takeover.

Pattern (regex-API `scan()`, stdlib only):
    1. The contract defines `function _authorizeUpgrade(` with a body.
    2. NEGATIVE PRECONDITION: the body contains NO access-control evidence -
       no `onlyOwner`/`onlyRole`/`onlyGovernance`-style modifier on the
       signature, no `require(`/`if (...) revert`, no
       `_checkOwner()`/`_checkRole(`, no `msg.sender ==` comparison.

If (1) AND (2) -> flag. High. (If a modifier is on the signature the
detector treats it as protected and skips.)

Sibling: `detectors/fixtures/missing_access_control_on_authorizeupgrade`.
This detector is the regex-API, body-shape complement that also catches
the empty-body case the modifier-only AST check can miss.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "upgrade-authorize-upgrade-unprotected"


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


_AUTH_FN_RE = re.compile(r"\bfunction\s+(_authorizeUpgrade)\s*\(")
_ACCESS_MOD_RE = re.compile(
    r"\b(?:onlyOwner|onlyRole|onlyGovernance|onlyAdmin|onlyGov|"
    r"onlyTimelock|requiresAuth|auth|restricted|onlyDAO|onlyMultisig)\b"
)
_REQUIRE_RE = re.compile(r"\brequire\s*\(")
_REVERT_RE = re.compile(r"\brevert\b")
_CHECK_HELPER_RE = re.compile(r"\b_check(?:Owner|Role)\s*\(")
_SENDER_CMP_RE = re.compile(r"msg\.sender\s*==|==\s*msg\.sender")


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    source = _strip_comments(source)
    findings: List[Finding] = []
    if "_authorizeUpgrade" not in source:
        return findings

    for m in _AUTH_FN_RE.finditer(source):
        # parse signature region up to `{` or `;`
        i = m.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            if source[i] == "(":
                depth_paren += 1
            elif source[i] == ")":
                depth_paren -= 1
            i += 1
        j = i
        while j < len(source) and source[j] not in "{;":
            j += 1
        if j >= len(source) or source[j] == ";":
            continue  # abstract / interface declaration
        sig_region = source[i:j]
        # protected by an access-control modifier on the signature.
        if _ACCESS_MOD_RE.search(sig_region):
            continue
        # balanced body
        depth = 1
        k = j + 1
        while k < len(source) and depth > 0:
            c = source[k]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            k += 1
        body = source[j + 1:k - 1]
        has_check = (
            _REQUIRE_RE.search(body)
            or _REVERT_RE.search(body)
            or _CHECK_HELPER_RE.search(body)
            or _SENDER_CMP_RE.search(body)
            or _ACCESS_MOD_RE.search(body)
        )
        if has_check:
            continue
        line = source.count("\n", 0, m.start()) + 1
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=line,
                severity="High",
                function="_authorizeUpgrade",
                message=(
                    "UUPS `_authorizeUpgrade` override has no access control: "
                    "no `onlyOwner`/`onlyRole` modifier, no `require`, no "
                    "`revert`, no `_checkOwner`/`_checkRole`, no `msg.sender` "
                    "check. `upgradeToAndCall` is therefore callable by anyone "
                    "- an attacker can swap in a malicious logic contract and "
                    "take over the proxy. Gate the hook with owner/role auth."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME"]
