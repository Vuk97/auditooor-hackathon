"""
initialize-frontrun-owner-takeover - narrow regex detector.

Confirmed corpus anchors:
- Solodit #25543 (Code4rena / Notional NoteERC20.initialize)
- Solodit #31467 (Pashov / Hytopia wallet initialize frontrun)

This detector targets one specific shape:
1. A public or external initialize-style function.
2. The function is initializer-shaped (`initializer`, `reinitializer`,
   or the file imports `Initializable`).
3. The body assigns owner/admin/controller/governor authority from
   caller-controlled input or `msg.sender`.
4. There is no visible factory/deployer binding on the signature or in
   the body.

If that shape appears, a mempool frontrunner can call initialize first
and seize ownership or equivalent authority before the intended deployer
does.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "initialize-frontrun-owner-takeover"


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
    return _LINE_COMMENT_RE.sub("", _BLOCK_COMMENT_RE.sub("", src))


_INIT_FN_RE = re.compile(r"\bfunction\s+(?P<name>initialize|init|setup|setUp)\s*\(", re.I)
_INITIALIZER_SHAPE_RE = re.compile(r"\b(?:initializer|reinitializer\s*\()")
_PUBLIC_OR_EXTERNAL_RE = re.compile(r"\b(?:public|external)\b")
_AUTH_ASSIGN_RE = re.compile(
    r"\b(?:owner|admin|controller|governor)\s*=\s*"
    r"(?:msg\.sender|_?owner|owner_|_?admin|admin_|initialOwner|initialAdmin|"
    r"initialController|initialGovernor|controller_|governor_)\b"
)
_OWNABLE_INIT_RE = re.compile(
    r"\b(?:__Ownable_init|_transferOwnership|transferOwnership)\s*\(\s*"
    r"(?:msg\.sender|_?owner|owner_|initialOwner)\s*\)"
)
_FACTORY_BINDING_RE = re.compile(
    r"\b(?:onlyFactory|onlyDeployer|initializerOnlyFactory|trustedFactory|"
    r"deployerAddress|expectedDeployer|factoryOnly|onlyProxyFactory)\b|"
    r"msg\.sender\s*==\s*(?:factory|_factory|trustedFactory|deployer|_deployer|"
    r"expectedDeployer)|"
    r"(?:factory|_factory|trustedFactory|deployer|_deployer|expectedDeployer)"
    r"\s*==\s*msg\.sender"
)


def _find_block(source: str, open_idx: int) -> str:
    depth = 1
    k = open_idx + 1
    while k < len(source) and depth > 0:
        c = source[k]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        k += 1
    return source[open_idx + 1 : k - 1]


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    source = _strip_comments(source)
    findings: List[Finding] = []
    if "initialize" not in source and "Initializable" not in source:
        return findings

    for match in _INIT_FN_RE.finditer(source):
        name = match.group("name")
        i = match.end()
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
            continue
        sig_region = source[i:j]
        if not _PUBLIC_OR_EXTERNAL_RE.search(sig_region):
            continue
        if "Initializable" not in source and not _INITIALIZER_SHAPE_RE.search(sig_region):
            continue
        if _FACTORY_BINDING_RE.search(sig_region):
            continue

        body = _find_block(source, j)
        if _FACTORY_BINDING_RE.search(body):
            continue
        if not (_AUTH_ASSIGN_RE.search(body) or _OWNABLE_INIT_RE.search(body)):
            continue

        line = source.count("\n", 0, match.start()) + 1
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=line,
                severity="High",
                function=name,
                message=(
                    "Public initialize-style function assigns owner-like authority "
                    "from caller-controlled input or `msg.sender` without a visible "
                    "factory/deployer binding. A frontrunner can initialize first "
                    "and seize ownership or equivalent control."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME"]
