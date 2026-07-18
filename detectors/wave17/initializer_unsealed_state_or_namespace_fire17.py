"""
initializer-unsealed-state-or-namespace-fire17

Detects Solidity initializer-front-run recall misses where a public
initializer, setup, registration, or migration entrypoint writes durable owner,
namespace, index, route, or cross-chain account state without binding the
caller to the intended actor or to a versioned migration order.

This detector is candidate evidence only. It deliberately does not treat an
`initializer` modifier by itself as safe: it seals after the first call, but
does not prove that the first caller is the deployer, factory, owner,
governance, or expected migration actor.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "initializer-unsealed-state-or-namespace-fire17"
DETECTOR_SEVERITY_DEFAULT = "High"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b")
_INIT_LIKE_NAME_RE = re.compile(
    r"(?i)("
    r"^(?:initialize|init|setup|bootstrap|configure|register|seed|migrate|"
    r"upgrade|rescale|reset)(?:[A-Z_].*)?$|"
    r"^(?:setInitial|setGenesis|setNamespace|initReserve|initPool|"
    r"initializeReserve|initializeAccount|registerAccount|migrateNamespace|"
    r"seedIndex|seedReserveIndex)\w*$"
    r")"
)

_DURABLE_CONTEXT_RE = re.compile(
    r"(?is)("
    r"owner|admin|authority|governor|guardian|controller|manager|operator|"
    r"factory|deployer|namespace|erc7201|layout\s*\(\s*\)|_STORAGE_SLOT|"
    r"NAMESPACE|liquidityIndex|variableBorrowIndex|borrowIndex|supplyIndex|"
    r"cumulativeIndex|reserveData|accountOwner|accountFor|remoteAccount|"
    r"chainAccount|remoteChain|localAccount|trustedRemote|peer|counterpart|"
    r"gateway|route|bridge|chainId|domain|version|initialized"
    r")"
)

_DURABLE_WRITE_RE = re.compile(
    r"(?is)("
    r"(?:layout\s*\(\s*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*"
    r"(?:owner|admin|authority|governor|guardian|controller|manager|operator|"
    r"namespace|version|initialized|remoteAccount|remoteGateway|gateway|peer|"
    r"counterpart)\s*=|"
    r"(?:accountOwner|accountFor|chainAccount|remoteAccounts?|localAccounts?|"
    r"trustedRemoteLookup|trustedRemotes?|gatewayFor|routeFor|routes?|"
    r"chainGateways?|registeredChains?|knownChains?|migratedChains?)"
    r"\s*\[[^;{}]+\]\s*=|"
    r"(?:reserveData|reserves|markets|assets)\s*\[[^;{}]+\]\s*\.\s*"
    r"(?:liquidityIndex|variableBorrowIndex|borrowIndex|supplyIndex|"
    r"cumulativeIndex|initialized)\s*=|"
    r"\b(?:owner|admin|authority|guardian|controller|namespace|"
    r"liquidityIndex|variableBorrowIndex|borrowIndex|supplyIndex|"
    r"cumulativeIndex|remoteGateway|trustedRemote|initializedVersion|"
    r"migrationVersion)\b\s*="
    r")"
)

_AUTH_BINDING_RE = re.compile(
    r"(?is)("
    r"\b(?:onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|"
    r"onlyDeployer|onlyConfigurator|onlyPoolConfigurator|onlyRole|"
    r"onlyBridgeAdmin|requiresAuth|auth|restricted)\b|"
    r"\b_checkOwner\s*\(|\b_checkRole\s*\(|\bhasRole\s*\(|"
    r"\brequire\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^;{}]*(?:owner|admin|governance|governor|deployer|factory|"
    r"configurator|guardian|authority|controller|registry|expectedActor)|"
    r"\brequire\s*\([^;{}]*(?:owner|admin|governance|governor|deployer|"
    r"factory|configurator|guardian|authority|controller|registry|"
    r"expectedActor)[^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))|"
    r"\bif\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^;{}]*!=[^;{}]*(?:owner|admin|governance|governor|deployer|factory|"
    r"configurator|guardian|authority|controller|registry|expectedActor)"
    r"[^;{}]*\)\s*revert|"
    r"\bif\s*\([^;{}]*(?:owner|admin|governance|governor|deployer|factory|"
    r"configurator|guardian|authority|controller|registry|expectedActor)"
    r"[^;{}]*!=[^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^;{}]*\)\s*revert"
    r")"
)

_VERSION_OR_ORDER_RE = re.compile(
    r"(?is)("
    r"\breinitializer\s*\(|"
    r"\brequire\s*\([^;{}]*(?:version|migrationVersion|initializedVersion)"
    r"[^;{}]*(?:==|!=|<|<=|>|>=)[^;{}]*[0-9A-Z_]|"
    r"\brequire\s*\([^;{}]*[0-9A-Z_][^;{}]*(?:==|!=|<|<=|>|>=)"
    r"[^;{}]*(?:version|migrationVersion|initializedVersion)|"
    r"\bif\s*\([^;{}]*(?:version|migrationVersion|initializedVersion)"
    r"[^;{}]*(?:==|!=|<|<=|>|>=)[^;{}]*\)\s*revert|"
    r"\b(?:version|migrationVersion|initializedVersion)\s*=\s*[0-9A-Z_]+"
    r")"
)

_MONOTONIC_INDEX_RE = re.compile(
    r"(?is)("
    r"\brequire\s*\([^;{}]*(?:newIndex|index|nextIndex)"
    r"[^;{}]*>=\s*(?:oldIndex|currentIndex|previousIndex|"
    r".*(?:liquidityIndex|variableBorrowIndex|borrowIndex|supplyIndex|"
    r"cumulativeIndex))|"
    r"\bassert\s*\([^;{}]*(?:newIndex|index|nextIndex)[^;{}]*>=|"
    r"\boldIndex\b|\bpreviousIndex\b|\bcurrentIndex\b"
    r")"
)

_LOCAL_DECL_PREFIX_RE = re.compile(
    r"(?is)(?:uint(?:8|16|32|64|128|256)?|int(?:8|16|32|64|128|256)?|"
    r"bool|address|bytes(?:[0-9]+)?|string)\s+$"
)


def _strip_comments_preserve(source: str) -> str:
    def repl(match: re.Match[str]) -> str:
        text = match.group(0)
        return "".join("\n" if ch == "\n" else " " for ch in text)

    return _COMMENT_RE.sub(repl, source)


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


def _is_local_declaration(body: str, start: int) -> bool:
    prefix = body[max(0, start - 80):start]
    prefix = prefix.rsplit(";", 1)[-1]
    prefix = prefix.rsplit("{", 1)[-1]
    return bool(_LOCAL_DECL_PREFIX_RE.search(prefix))


def _durable_write_match(body: str) -> Optional[re.Match[str]]:
    for match in _DURABLE_WRITE_RE.finditer(body):
        if _is_local_declaration(body, match.start()):
            continue
        return match
    return None


def _has_safe_binding_or_order(header_and_body: str) -> bool:
    if _AUTH_BINDING_RE.search(header_and_body):
        return True
    if _VERSION_OR_ORDER_RE.search(header_and_body):
        return True
    if _MONOTONIC_INDEX_RE.search(header_and_body):
        return True
    return False


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    clean_source = _strip_comments_preserve(source)
    findings: List[Finding] = []
    for function_name, header, body, function_line in _split_functions(clean_source):
        header_and_body = f"{header}\n{body}"
        if not _PUBLIC_HEADER_RE.search(header):
            continue
        if _VIEW_HEADER_RE.search(header):
            continue
        if not _INIT_LIKE_NAME_RE.search(function_name):
            continue
        if not _DURABLE_CONTEXT_RE.search(header_and_body):
            continue

        write_match = _durable_write_match(body)
        if write_match is None:
            continue
        if _has_safe_binding_or_order(header_and_body):
            continue

        line = function_line + body.count("\n", 0, write_match.start())
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=line,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=function_name,
                message=(
                    f"`{function_name}` writes durable initializer, namespace, "
                    "index, route, or cross-chain account state without caller "
                    "binding or versioned order protection. Bind the entrypoint "
                    "to the intended actor, initialize atomically, or add an "
                    "explicit version or monotonicity guard before writing this "
                    "persistent state."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
