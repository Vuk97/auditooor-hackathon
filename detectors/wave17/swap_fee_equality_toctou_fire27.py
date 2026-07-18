"""
swap-fee-equality-toctou-fire27

Fire27 Solidity detector for swap, hook, or fee paths that check equality
or snapshot a fee/config value before an external hook or mutable call, then
reuse the checked value after the call can change fee/config state.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:5a4dc5fcabec4193
- context_pack_hash: 5a4dc5fcabec419385f40cc3f83d3a24f63a01e0d5c301ab1ef08763094a3fe5
- source ref: reference/patterns.dsl/fx-v4core-swap-fee-equality-check.yaml
- source ref: reference/patterns.dsl/erc4337-paymaster-no-sender-validation.yaml
- source ref: reference/patterns.dsl/r94-reverse-withdraw-transfer-failure-swallowed.yaml
- attack_class: state-change-between-check-and-use

Hits are candidate evidence only. NOT_SUBMIT_READY. The detector requires
fee/swap/hook/config vocabulary, a real external call boundary, and post-call
reuse of the checked value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "swap-fee-equality-toctou-fire27"
DETECTOR_SEVERITY_DEFAULT = "Medium"


@dataclass(frozen=True)
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


@dataclass(frozen=True)
class FunctionSlice:
    name: str
    header: str
    body: str
    line: int


@dataclass(frozen=True)
class CandidateValue:
    identity: str
    line_offset: int
    source: str


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b")
_VIEW_OR_PURE_RE = re.compile(r"\b(?:view|pure)\b")
_SKIP_FUNCTION_RE = re.compile(r"(?i)^(?:test|setUp|mock|fixture|harness)")
_FEE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:swap|exactInput|exactOutput|amountSpecified|fee|fees|"
    r"swapFee|lpFee|protocolFee|hook|beforeSwap|afterSwap|poolManager|"
    r"feeConfig|dynamicFee|config|configuration|MAX_SWAP_FEE|MAX_LP_FEE)\b"
)
_ENTRY_CONTEXT_RE = re.compile(
    r"(?is)\b(?:swap|fee|hook|settle|collect|modify|beforeSwap|afterSwap|quote)\b"
)
_EXTERNAL_BOUNDARY_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\bI[A-Za-z0-9_]*(?:Hook|Router|Manager|Config|Controller|Swap|Fee)"
    r"[A-Za-z0-9_]*\s*\([^;{}]*\)\s*\.\s*"
    r"(?:before|after|on|update|set|sync|swap|modify|collect|settle|execute|callback)"
    r"[A-Za-z0-9_]*\s*\(|"
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:\[[^\]]+\]|\.\s*[A-Za-z_][A-Za-z0-9_]*))*"
    r"\s*\.\s*"
    r"(?:before|after|on|update|set|sync|swap|modify|collect|settle|execute|callback)"
    r"[A-Za-z0-9_]*\s*\(|"
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\])?\s*\.\s*"
    r"(?:call|delegatecall)\s*(?:\{|\()"
    r")"
)
_EQ_CHECK_RE = re.compile(
    r"(?is)\b(?:require|assert|if)\s*\((?P<expr>[^;{}]*(?:==|!=)[^;{}]*)\)"
)
_IDENTITY_RE = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\s*(?:\[[^\];{}]+\]|\.\s*[A-Za-z_][A-Za-z0-9_]*))*"
)
_FEE_IDENTITY_RE = re.compile(r"(?i)(?:fee|config|hook)")
_CONSTANT_RE = re.compile(r"^(?:MAX|MIN|DEFAULT|ZERO|ONE|BPS|FEE_DENOMINATOR|PIPS)[A-Z0-9_]*$")
_SNAPSHOT_RE = re.compile(
    r"(?is)(?:^|[;\n{])\s*"
    r"(?:(?P<type>"
    r"uint(?:8|16|24|32|64|128|256)?|int(?:8|16|24|32|64|128|256)?|"
    r"bool|address|bytes32|[A-Za-z_][A-Za-z0-9_]*(?:Fee|Config|Hook)[A-Za-z0-9_]*"
    r")\s+(?P<loc>memory|storage|calldata)?\s+)?"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<rhs>[^;]*(?:fee|Fee|config|Config|hook|Hook|swapFee|lpFee|protocolFee)[^;]*);"
)
_REVALIDATION_STATE_RE = re.compile(
    r"(?is)(?:\.\s*(?:swapFee|lpFee|protocolFee|hookFee|dynamicFee|fee|config)|"
    r"\b(?:get|read|load|current|latest)[A-Za-z0-9_]*(?:Fee|Config|Hook)\b|"
    r"\bfeeConfig\b|\bpoolConfig\b|\bconfigOf\b)"
)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    if open_brace < 0 or open_brace >= len(source) or source[open_brace] != "{":
        return None, open_brace
    depth = 1
    i = open_brace + 1
    while i < len(source) and depth > 0:
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
        i += 1
    if depth != 0:
        return None, open_brace
    return source[open_brace + 1:i - 1], i


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
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

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        line = source.count("\n", 0, match.start()) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, line=line))
        pos = end_pos
    return out


def _normalise_identity(identity: str) -> str:
    return re.sub(r"\s+", "", identity or "")


def _identity_regex(identity: str) -> re.Pattern[str]:
    norm = _normalise_identity(identity)
    if "." in norm:
        return re.compile(r"\s*\.\s*".join(re.escape(part) for part in norm.split(".")))
    return re.compile(rf"(?<!\.)\b{re.escape(norm)}\b")


def _is_fee_identity(identity: str) -> bool:
    norm = _normalise_identity(identity)
    if not norm or _CONSTANT_RE.fullmatch(norm):
        return False
    return bool(_FEE_IDENTITY_RE.search(norm))


def _line_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, max(offset, 0))


def _statement_around(text: str, offset: int) -> str:
    start = max(text.rfind(";", 0, offset), text.rfind("{", 0, offset), text.rfind("\n", 0, offset))
    end = text.find(";", offset)
    if end == -1:
        end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    return text[start + 1:end + 1]


def _extract_fee_identities(expr: str) -> list[str]:
    out: list[str] = []
    for match in _IDENTITY_RE.finditer(expr):
        ident = _normalise_identity(match.group(0))
        if not _is_fee_identity(ident):
            continue
        if ident not in out:
            out.append(ident)
    return out


def _checked_values_before_boundary(pre_text: str) -> list[CandidateValue]:
    values: list[CandidateValue] = []
    seen: set[tuple[str, str]] = set()

    for match in _EQ_CHECK_RE.finditer(pre_text):
        expr = match.group("expr")
        if not _FEE_CONTEXT_RE.search(expr):
            continue
        for identity in _extract_fee_identities(expr):
            key = (identity, "equality")
            if key in seen:
                continue
            seen.add(key)
            values.append(
                CandidateValue(
                    identity=identity,
                    line_offset=_line_offset(pre_text, match.start()),
                    source="fee/config equality check",
                )
            )

    for match in _SNAPSHOT_RE.finditer(pre_text):
        var_name = match.group("var")
        rhs = match.group("rhs") or ""
        type_name = match.group("type") or ""
        if (match.group("loc") or "").lower() == "storage":
            continue
        if not (_FEE_CONTEXT_RE.search(var_name) or _FEE_CONTEXT_RE.search(type_name) or _FEE_CONTEXT_RE.search(rhs)):
            continue
        identity = _normalise_identity(var_name)
        if _CONSTANT_RE.fullmatch(identity):
            continue
        key = (identity, "snapshot")
        if key in seen:
            continue
        seen.add(key)
        values.append(
            CandidateValue(
                identity=identity,
                line_offset=_line_offset(pre_text, match.start()),
                source="fee/config snapshot",
            )
        )
    return values


def _is_reload_statement(statement: str, identity: str) -> bool:
    ident_re = re.escape(_normalise_identity(identity))
    return bool(
        re.search(
            rf"(?is)^\s*(?:[A-Za-z_][A-Za-z0-9_]*(?:\s+(?:memory|storage|calldata))?\s+)?"
            rf"{ident_re}\s*=\s*[^;]*(?:fee|Fee|config|Config|hook|Hook)[^;]*;",
            statement,
        )
    )


def _is_revalidation_statement(statement: str, identity: str) -> bool:
    if "==" not in statement:
        return False
    if not _identity_regex(identity).search(statement):
        return False
    if not re.search(r"(?is)\b(?:require|assert|if)\s*\(", statement):
        return False
    return bool(_REVALIDATION_STATE_RE.search(statement))


def _is_lhs_only_assignment(statement: str, identity: str) -> bool:
    ident_re = re.escape(_normalise_identity(identity))
    return bool(re.search(rf"(?is)^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?{ident_re}\s*(?:=|\+=|-=)", statement))


def _post_boundary_stale_use(tail: str, identity: str) -> Optional[int]:
    identity_re = _identity_regex(identity)
    refreshed = False
    for match in identity_re.finditer(tail):
        statement = _statement_around(tail, match.start())
        if _is_reload_statement(statement, identity) or _is_revalidation_statement(statement, identity):
            refreshed = True
            continue
        if refreshed:
            return None
        if _is_lhs_only_assignment(statement, identity):
            continue
        return match.start()
    return None


def _is_candidate_function(fn: FunctionSlice) -> bool:
    if _SKIP_FUNCTION_RE.search(fn.name):
        return False
    if not _CALLABLE_HEADER_RE.search(fn.header):
        return False
    if _VIEW_OR_PURE_RE.search(fn.header):
        return False
    surface = f"{fn.name}\n{fn.header}\n{fn.body}"
    return bool(_FEE_CONTEXT_RE.search(surface) and _ENTRY_CONTEXT_RE.search(surface))


def _match_function(fn: FunctionSlice) -> tuple[int, str, str] | None:
    for boundary in _EXTERNAL_BOUNDARY_RE.finditer(fn.body):
        pre_text = fn.body[:boundary.start()]
        tail = fn.body[boundary.end():]
        if not _FEE_CONTEXT_RE.search(pre_text):
            continue
        if not _FEE_CONTEXT_RE.search(tail):
            continue

        for candidate in _checked_values_before_boundary(pre_text):
            use_offset = _post_boundary_stale_use(tail, candidate.identity)
            if use_offset is None:
                continue
            boundary_text = re.sub(r"\s+", " ", boundary.group(0)).strip()
            return (
                candidate.line_offset,
                candidate.identity,
                f"{candidate.source} crosses external boundary `{boundary_text[:90]}`",
            )
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    findings: list[Finding] = []
    if not _FEE_CONTEXT_RE.search(source or ""):
        return findings

    clean_source = _strip_comments_and_strings(source)
    if not _FEE_CONTEXT_RE.search(clean_source):
        return findings

    for fn in _split_functions(clean_source):
        if not _is_candidate_function(fn):
            continue
        matched = _match_function(fn)
        if matched is None:
            continue
        line_offset, identity, reason = matched
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=fn.line + line_offset,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` has a swap fee/config state-change-between-check-and-use "
                    f"boundary: `{identity}` is checked or snapshotted before an external "
                    f"hook or mutable call and reused after it. {reason}. Reload and "
                    "revalidate the fee/config value after the hook before swap settlement. "
                    "NOT_SUBMIT_READY detector_fixture_smoke_only."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
