"""
initializer-front-run-first-writer-fire26

Regex recall-lift detector for externally callable setup paths where the
first caller writes critical configuration behind only an unset or initialized
sentinel. Candidate evidence only.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:adfd418d3f6192da
- context_pack_hash: adfd418d3f6192daba631fcbdf76e5215584274de62029de0f3d710f7f613f3b
- queue evidence: rwrq-initializer-front-run-c1b374394097
- source refs:
  - reference/patterns.dsl/cross-chain-aa-address-symmetry.yaml
  - reference/patterns.dsl/fx-morpho-create-market-irm-zero-call.yaml
  - reference/patterns.dsl/fx-pendle-uninitialized-return-array.yaml

This detector intentionally targets the first-writer storage subshape. The
cross-chain address-symmetry and uninitialized-return-array refs are retained
as boundary evidence because existing exact detectors already cover those
adjacent initialization misses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "initializer-front-run-first-writer-fire26"
DETECTOR_SEVERITY_DEFAULT = "High"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b")
_ENTRYPOINT_NAME_RE = re.compile(
    r"(?i)^(?:initialize|init|setup|bootstrap|configure|register|create|add|set|migrate)"
    r"[A-Za-z0-9_]*(?:Owner|Admin|Authority|Implementation|Impl|Registry|Route|Path|"
    r"Chain|Domain|Endpoint|Peer|Remote|Gateway|Bridge|Market|Config|Module)?$|"
    r"^(?:createMarket|registerMarket|initializeMarket|setImplementation|setRegistry)$"
)
_PARAM_RE = re.compile(
    r"(?is)(?:^|,)\s*"
    r"(?P<type>"
    r"(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?|"
    r"bytes(?:[0-9]+)?|uint(?:[0-9]+)?|int(?:[0-9]+)?|address|string|bool)"
    r"(?:\s*\[[^\]]*\])?"
    r")\s+"
    r"(?:(?:calldata|memory|storage)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_FIRST_WRITER_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:initializer|reinitializer)\b|"
    r"\brequire\s*\([^;{}]*(?:!\s*_?initialized|_?initialized\s*==\s*false|"
    r"_?initialized\s*!=\s*true)[^;{}]*\)|"
    r"\b(?:if|require)\s*\([^;{}]*(?:owner|admin|authority|implementation|registry|"
    r"router|oracle|gateway|peer|remote|endpoint|market|lastUpdate|created|route)"
    r"[^;{}]*(?:==|!=)\s*(?:address\s*\(\s*0\s*\)|0|false|bytes32\s*\(\s*0\s*\))"
    r"[^;{}]*\)|"
    r"\b(?:if|require)\s*\([^;{}]*(?:routes?|gateways?|gatewayFor|destinationOf|"
    r"idToMarketParams|marketParamsById|markets?|registries|implementations)"
    r"\s*\[[^;{}]+\][^;{}]*(?:==|!=)\s*(?:address\s*\(\s*0\s*\)|0|false|"
    r"bytes32\s*\(\s*0\s*\))[^;{}]*\)|"
    r"\b(?:initialized|_initialized|created|isCreated)\s*=\s*true\b"
    r")"
)
_AUTH_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|onlyDeployer|"
    r"onlyRole|onlyRoles|onlyProxy|onlyInitializing|requiresAuth|requireAuth|"
    r"restricted|auth)\b|"
    r"\b(?:_checkOwner|_checkRole|_authorize|hasRole|isOwner|isAdmin)\s*\(|"
    r"\brequire\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\)|tx\.origin)"
    r"[^;{}]*(?:owner|admin|governance|governor|deployer|factory|authority|"
    r"controller|manager|operator|registry)|"
    r"\brequire\s*\([^;{}]*(?:owner|admin|governance|governor|deployer|factory|"
    r"authority|controller|manager|operator|registry)[^;{}]*(?:msg\.sender|"
    r"_msgSender\s*\(\s*\)|tx\.origin)|"
    r"\bif\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))\s*!=\s*"
    r"(?:owner|admin|governance|governor|deployer|factory|authority|controller|"
    r"manager|operator|registry)[^;{}]*\)\s*revert"
    r")"
)
_ASSIGN_RE = re.compile(
    r"(?is)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^;\n]+\])?"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?)\s*=\s*(?P<rhs>[^;\n]+);"
)
_CRITICAL_LHS_RE = re.compile(
    r"(?i)(owner|admin|authority|governance|governor|guardian|controller|manager|"
    r"operator|factory|registry|router|oracle|irm|market|implementation|beacon|"
    r"proxy|recipient|receiver|destination|remote|gateway|bridge|peer|counterpart|"
    r"route|path|chain|domain|eid|module|returnArray|amountOuts|idToMarketParams)"
)
_CALLER_CONTROLLED_RE = re.compile(r"(?is)\b(?:msg\.sender|_msgSender\s*\(\s*\)|tx\.origin)\b")
_MARKET_VALIDATION_RE = re.compile(
    r"(?is)(?:"
    r"(?:marketParams|params|input|config)\s*\.\s*irm\s*!=\s*address\s*\(\s*0\s*\)|"
    r"address\s*\(\s*0\s*\)\s*!=\s*(?:marketParams|params|input|config)\s*\.\s*irm|"
    r"\b(?:_validateMarket|validateMarket|_checkMarket|checkMarket|validateMarketParams)"
    r"\s*\("
    r")"
)
_NONZERO_RHS_RE = re.compile(
    r"(?is)^(?:address\s*\(\s*0\s*\)|0|false|bytes32\s*\(\s*0\s*\)|"
    r"new\s+[A-Za-z_][A-Za-z0-9_]*\s*\[)"
)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _split_functions(source: str) -> list[tuple[str, str, str, int]]:
    out: list[tuple[str, str, str, int]] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        i = match.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            if source[i] == "(":
                depth_paren += 1
            elif source[i] == ")":
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
            pos = max(i, j)
            continue

        depth = 1
        k = body_start + 1
        while k < len(source) and depth > 0:
            if source[k] == "{":
                depth += 1
            elif source[k] == "}":
                depth -= 1
            k += 1

        header = source[match.start():body_start]
        body = source[body_start + 1:k - 1]
        line = source.count("\n", 0, match.start()) + 1
        out.append((name, header, body, line))
        pos = k
    return out


def _is_external_entry(header: str) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(header)) and not _VIEW_HEADER_RE.search(header)


def _parameter_section(header: str) -> str:
    start = header.find("(")
    if start < 0:
        return ""
    depth = 1
    i = start + 1
    while i < len(header) and depth > 0:
        if header[i] == "(":
            depth += 1
        elif header[i] == ")":
            depth -= 1
        i += 1
    if depth != 0:
        return ""
    return header[start + 1:i - 1]


def _param_names(header: str) -> set[str]:
    return {match.group("name") for match in _PARAM_RE.finditer(_parameter_section(header))}


def _rhs_is_caller_controlled(rhs: str, params: set[str]) -> bool:
    if _CALLER_CONTROLLED_RE.search(rhs):
        return True
    return any(re.search(rf"(?<![A-Za-z0-9_]){re.escape(param)}(?![A-Za-z0-9_])", rhs) for param in params)


def _is_market_param_write(lhs: str, rhs: str) -> bool:
    return bool(re.search(r"(?i)(market|irm|idToMarketParams)", lhs) or re.search(r"(?i)(marketParams|\.irm\b)", rhs))


def _critical_writes(
    body: str,
    params: set[str],
) -> list[tuple[str, str, int]]:
    writes: list[tuple[str, str, int]] = []
    for match in _ASSIGN_RE.finditer(body):
        lhs = re.sub(r"\s+", "", match.group("lhs"))
        rhs = match.group("rhs").strip()
        if not _CRITICAL_LHS_RE.search(lhs):
            continue
        if _NONZERO_RHS_RE.search(rhs):
            continue
        if not _rhs_is_caller_controlled(rhs, params):
            continue
        if _is_market_param_write(lhs, rhs) and _MARKET_VALIDATION_RE.search(body):
            continue
        writes.append((lhs, rhs[:120], match.start()))
    return writes


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for function_name, header, body, function_line in _split_functions(stripped):
        header_and_body = f"{header}\n{body}"
        if not _is_external_entry(header):
            continue
        if not _ENTRYPOINT_NAME_RE.search(function_name):
            continue
        if not _FIRST_WRITER_RE.search(header_and_body):
            continue
        if _AUTH_GUARD_RE.search(header_and_body):
            continue

        params = _param_names(header)
        writes = _critical_writes(body, params)
        if not writes:
            continue

        lhs, rhs, offset = writes[0]
        line = function_line + body.count("\n", 0, offset)
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=line,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=function_name,
                message=(
                    f"`{function_name}` first-writes critical setup state `{lhs}` "
                    f"from caller-controlled input `{rhs}` behind only an unset "
                    "or initialized sentinel, with no owner, factory, role, or "
                    "onlyInitializing binding."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
