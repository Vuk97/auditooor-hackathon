"""
storage-namespace-first-caller-authority-init-fire15

Detects a narrow initializer-front-run recall shape: a public initializer or
setup route writes authority into an ERC-7201 style storage namespace behind
only an initialized or first-write guard. If the function is not bound to a
factory, deployer, owner, governance, or role, the first caller can set the
authority fields before the intended deployment transaction lands.

This is candidate evidence only. It does not prove exploitability or filing
readiness without a real protocol path and a negative control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "storage-namespace-first-caller-authority-init-fire15"
DETECTOR_SEVERITY_DEFAULT = "High"


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
_INIT_NAME_RE = re.compile(
    r"(?i)^(?:initialize|init|setup|bootstrap)(?:[A-Z_].*)?$|"
    r"^(?:configure|register)(?:Namespace|Account|Module|Authority|Role)$"
)
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_NAMESPACE_RE = re.compile(
    r"(?is)\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?layout\s*\(\s*\)|"
    r"\b(?:Storage|Layout|State)\s+storage\s+[A-Za-z_$][A-Za-z0-9_$]*|"
    r"\berc7201\b|"
    r"\b_STORAGE_SLOT\b|"
    r"\bNAMESPACE\b"
)
_AUTHORITY_WRITE_RE = re.compile(
    r"(?is)(?:[A-Za-z_$][A-Za-z0-9_$]*\.)"
    r"(?:owner|admin|authority|governor|guardian|controller|manager|operator)"
    r"\s*=\s*(?:msg\.sender|_?[A-Za-z_][A-Za-z0-9_]*)|"
    r"\b_(?:grantRole|setupRole)\s*\(\s*DEFAULT_ADMIN_ROLE\s*,"
)
_INIT_GUARD_RE = re.compile(
    r"(?is)\b(?:initializer|reinitializer)\b|"
    r"\b(?:if|require)\s*\([^;{}]*(?:initialized|_initialized)"
    r"[^;{}]*(?:false|true|0|!)|"
    r"\b(?:if|require)\s*\([^;{}]*"
    r"(?:owner|admin|authority)\s*(?:==|!=)\s*address\s*\(\s*0\s*\)|"
    r"\b(?:initialized|_initialized)\s*=\s*true"
)
_AUTH_GUARD_RE = re.compile(
    r"(?is)\b(?:onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|"
    r"onlyDeployer|onlyRole|onlyBridgeAdmin|requiresAuth|auth)\b|"
    r"\b_checkOwner\s*\(|\b_checkRole\s*\(|\bhasRole\s*\(|"
    r"\brequire\s*\(\s*(?:msg\.sender|_msgSender\s*\(\s*\))\s*==\s*"
    r"(?:_?[A-Za-z0-9_]*(?:owner|admin|governance|governor|deployer|factory|"
    r"guardian|authority|controller|registry)[A-Za-z0-9_]*|owner\s*\(\s*\)|"
    r"admin\s*\(\s*\)|governance\s*\(\s*\))|"
    r"\bif\s*\(\s*(?:msg\.sender|_msgSender\s*\(\s*\))\s*!=\s*"
    r"(?:_?[A-Za-z0-9_]*(?:owner|admin|governance|governor|deployer|factory|"
    r"guardian|authority|controller|registry)[A-Za-z0-9_]*|owner\s*\(\s*\)|"
    r"admin\s*\(\s*\)|governance\s*\(\s*\))\s*\)\s*revert"
)


def _split_functions(source: str) -> List[tuple[str, str, str, int]]:
    out: List[tuple[str, str, str, int]] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if not match:
            break
        name = match.group("name")
        i = match.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            char = source[i]
            if char == "(":
                depth_paren += 1
            elif char == ")":
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
            char = source[k]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            k += 1
        header = source[match.start():body_start]
        body = source[body_start + 1:k - 1]
        function_line = source.count("\n", 0, match.start()) + 1
        out.append((name, header, body, function_line))
        pos = k
    return out


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    findings: List[Finding] = []
    for function_name, header, body, function_line in _split_functions(source):
        header_and_body = f"{header}\n{body}"
        if not _PUBLIC_HEADER_RE.search(header):
            continue
        if not _INIT_NAME_RE.search(function_name):
            continue
        if not _NAMESPACE_RE.search(header_and_body):
            continue
        authority_match = _AUTHORITY_WRITE_RE.search(body)
        if not authority_match:
            continue
        if not _INIT_GUARD_RE.search(header_and_body):
            continue
        if _AUTH_GUARD_RE.search(header_and_body):
            continue

        line = function_line + body.count("\n", 0, authority_match.start())
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=line,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=function_name,
                message=(
                    f"`{function_name}` writes namespace authority state behind "
                    "only an initializer or first-write guard. Add a factory, "
                    "deployer, owner, governance, or role binding before the "
                    "authority write so an arbitrary first caller cannot claim "
                    "the namespace."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
