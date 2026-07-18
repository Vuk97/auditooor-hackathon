"""
r94_loop_ownable_non_upgradeable_in_proxy.py

Flags source that inherits from non-upgradeable `Ownable` in a
contract that also has `initialize()` / `Initializable` / is used
behind a proxy — owner gets set in constructor (never runs in proxy
context), onlyOwner reads address(0).

Source: Solodit #42307 (C4 Covalent).
Class: ownable-non-upgradeable-in-proxy (both).
"""

from __future__ import annotations
import re
from _util import source_nocomment

_OZ_OWNABLE_NON_UPGRADEABLE_RE = re.compile(
    r'import\s+["\'][^"\']*openzeppelin[^"\']*/access/Ownable\.sol["\']|'
    r'use\s+openzeppelin::access::ownable::Ownable\b|'
    r"import\s+\{\s*Ownable\s*\}\s+from"
)
_PROXY_MARKER_RE = re.compile(
    r"Initializable|UUPSUpgradeable|TransparentUpgradeableProxy|"
    r"fn\s+initialize\s*\(|ContextUpgradeable"
)
_OZ_OWNABLE_UPGRADEABLE_RE = re.compile(
    r"OwnableUpgradeable|Ownable2StepUpgradeable"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    src = source_nocomment(source)
    if not _OZ_OWNABLE_NON_UPGRADEABLE_RE.search(src):
        return hits
    if not _PROXY_MARKER_RE.search(src):
        return hits
    if _OZ_OWNABLE_UPGRADEABLE_RE.search(src):
        return hits
    hits.append({
        "severity": "high",
        "line": 1,
        "col": 0,
        "snippet": src[:200],
        "message": (
            "Contract is upgradeable (Initializable / initialize() / UUPS) "
            "but imports non-upgradeable `Ownable` — constructor sets owner, "
            "never runs in proxy, onlyOwner reads address(0) "
            "(ownable-non-upgradeable-in-proxy). See Solodit #42307 (Covalent)."
        ),
    })
    return hits
