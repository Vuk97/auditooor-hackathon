"""
fund-loss-memory-writeback-fire35

Solidity recall-lift detector for fund-loss-via-arithmetic variants where a
storage struct or array element is copied into memory, mutated in fee, share,
debt, collateral, reward, or accounting math, and a value-bearing sink fires
before the mutated memory copy is written back to the source storage slot.

This is narrower than a generic storage-to-memory warning. It requires a later
transfer, mint, burn, settlement, finalization, or value-bearing accounting
sink in the same function.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:5a29d91bbce92794
- context_pack_hash: 5a29d91bbce92794762a8ed09f2250a9242a49986ce3809863c10a012720379d
- source ref: reports/detector_lift_fire34_20260605/post_priorities_all.md
- source ref: reference/patterns.dsl/fund-loss-via-arithmetic-value-math.yaml
- source ref: reference/patterns.dsl/library-memory-copy-not-writeback.yaml
- source ref: detectors/wave17/arithmetic_conversion_order_fire33.py
- attack_class: fund-loss-via-arithmetic

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "fund-loss-memory-writeback-fire35"
DETECTOR_SEVERITY_DEFAULT = "Medium"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"


try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
except Exception:  # pragma: no cover - regex scan remains usable without Slither.
    class AbstractDetector:  # type: ignore[no-redef]
        pass

    class DetectorClassification:  # type: ignore[no-redef]
        MEDIUM = "Medium"


@dataclass(frozen=True)
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None
    local: Optional[str] = None
    source_expr: Optional[str] = None
    branch: Optional[str] = None


@dataclass(frozen=True)
class FunctionSlice:
    name: str
    header: str
    body: str
    function_line: int
    body_line: int


@dataclass(frozen=True)
class CopyMutation:
    local: str
    source_expr: str
    access: str
    copied_type: str
    line: int
    branch: str
    sink: str


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_FUNCTION_BLOCK_START_RE = re.compile(
    r"(?is)\bfunction\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*\)[^{;]*\{"
)
_EXTERNAL_OR_PUBLIC_RE = re.compile(r"\b(?:external|public)\b")
_VIEW_OR_PURE_RE = re.compile(r"\b(?:view|pure)\b")
_TYPE_BLOCK_START_RE = re.compile(r"(?is)\b(?:struct|enum)\s+[A-Za-z_][A-Za-z0-9_]*[^{;]*\{")
_MEMORY_COPY_RE = re.compile(
    r"(?is)\b(?P<type>(?:(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"[A-Za-z_][A-Za-z0-9_]*)(?:\s*\[[^\]]*\])*)\s+memory\s+"
    r"(?P<local>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<src>[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:\[[^\]]+\]|\.[A-Za-z_][A-Za-z0-9_]*))*)\s*;"
)
_MUTATION_RE_TEMPLATE = (
    r"(?is)\b{local}\s*(?P<access>(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])+)"
    r"\s*(?P<op>\+=|-=|\*=|/=|%=|=|\+\+|--)\s*(?P<expr>[^;]*)\s*;"
)
_STATEMENT_SKIP_RE = re.compile(
    r"(?i)^\s*(?:pragma|import|using|event|error|modifier|constructor|"
    r"contract|interface|library|struct|enum)\b"
)
_VISIBILITY_OR_MODIFIER_RE = re.compile(
    r"(?i)\b(?:public|private|internal|external|constant|immutable|override)\b"
)
_VALUE_WORD_RE = re.compile(
    r"(?i)(?:asset|assets|amount|balance|balances|borrow|collateral|credit|"
    r"debit|debt|fee|fees|liabilit|liquidat|loan|mint|owed|payout|principal|"
    r"redeem|repay|reserve|reward|rewards|share|shares|stake|supply|token|"
    r"total|vault|withdraw)"
)
_ECONOMIC_FUNCTION_RE = re.compile(
    r"(?i)^(?:borrow|claim|close|collect|complete|debit|deposit|distribute|"
    r"finalize|harvest|liquidate|mint|payout|redeem|release|repay|settle|"
    r"swap|trade|withdraw)"
)
_TRANSFER_SINK_RE = re.compile(
    r"(?is)\b(?:safeTransferFrom|safeTransfer|transferFrom|transfer|sendValue|"
    r"_mint|mint|_burn|burn)\s*\([^;{}]{0,360}\)\s*;"
)
_FINALIZATION_SINK_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:finalized|settled|closed|completed|executed|released|claimed|processed)"
    r"[A-Za-z0-9_]*(?:\s*\[[^\]]+\]\s*){0,3}\s*=\s*"
    r"(?:true|[A-Za-z_][A-Za-z0-9_]*\.(?:Finalized|Settled|Closed|Complete|Completed|Released|Executed))|"
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\]\s*){0,3}\.\s*status\s*=\s*"
    r"[A-Za-z_][A-Za-z0-9_]*\.(?:Finalized|Settled|Closed|Complete|Completed|Released|Executed)|"
    r"\b(?:_?finalize|_?settle|_?complete|_?close|_?release|_?execute|_?process)"
    r"[A-Za-z0-9_]*\s*\([^;{}]{0,360}\)\s*;"
    r")"
)
_ACCOUNTING_SINK_RE = re.compile(
    r"(?is)(?<!\.)\b(?:account|asset|assets|balance|balances|claim|claimable|closed|"
    r"collateral|credit|debit|debt|fee|fees|finalized|liability|liquidat|"
    r"owed|payout|pending|principal|released|reserve|reward|rewards|settled|"
    r"share|shares|supply|total|vault|withdrawable)[A-Za-z0-9_]*"
    r"(?:\s*\[[^\]]+\]\s*){0,3}(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
    r"\s*(?:=|\+=|-=)[^;{}]{0,360}\s*;"
)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _find_matching_delimiter(source: str, open_pos: int, open_char: str, close_char: str) -> int:
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != open_char:
        return -1
    depth = 1
    index = open_pos + 1
    while index < len(source) and depth > 0:
        if source[index] == open_char:
            depth += 1
        elif source[index] == close_char:
            depth -= 1
        index += 1
    return index - 1 if depth == 0 else -1


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        open_paren = source.find("(", match.end() - 1)
        close_paren = _find_matching_delimiter(source, open_paren, "(", ")")
        if close_paren < 0:
            pos = match.end()
            continue

        body_start = -1
        scan_pos = close_paren + 1
        while scan_pos < len(source):
            if source[scan_pos] == ";":
                break
            if source[scan_pos] == "{":
                body_start = scan_pos
                break
            scan_pos += 1
        if body_start < 0:
            pos = max(scan_pos, close_paren + 1)
            continue

        body_end = _find_matching_delimiter(source, body_start, "{", "}")
        if body_end < 0:
            pos = body_start + 1
            continue

        out.append(
            FunctionSlice(
                name=name,
                header=source[match.start():body_start],
                body=source[body_start + 1:body_end],
                function_line=source.count("\n", 0, match.start()) + 1,
                body_line=source.count("\n", 0, body_start + 1) + 1,
            )
        )
        pos = body_end + 1
    return out


def _blank_balanced_blocks(source: str, start_re: re.Pattern[str]) -> str:
    chars = list(source)
    for match in start_re.finditer(source):
        open_brace = source.find("{", match.start())
        if open_brace == -1:
            continue
        end = _find_matching_delimiter(source, open_brace, "{", "}")
        if end < 0:
            continue
        for index in range(match.start(), end + 1):
            if chars[index] not in "\r\n":
                chars[index] = " "
    return "".join(chars)


def _declaration_surface(source: str) -> str:
    text = _blank_balanced_blocks(source, _FUNCTION_BLOCK_START_RE)
    text = _blank_balanced_blocks(text, _TYPE_BLOCK_START_RE)
    return text


def _extract_state_vars(source: str) -> set[str]:
    surface = _declaration_surface(source)
    state_vars: set[str] = set()
    for statement in surface.split(";"):
        mapping_match = re.search(
            r"(?is)\bmapping\s*\([^;]+?\)\s*"
            r"(?:(?:public|private|internal|external|constant|immutable|override)\s+)*"
            r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*$",
            statement.strip(),
        )
        if mapping_match:
            state_vars.add(mapping_match.group("name"))
            continue
        if _STATEMENT_SKIP_RE.search(statement):
            continue
        if "(" in statement:
            continue
        statement = re.sub(r"(?is)=.*$", "", statement).strip()
        if not statement:
            continue
        parts = [part for part in re.split(r"\s+", statement) if part]
        if len(parts) < 2:
            continue
        candidate = re.sub(r"\[[^\]]*\]$", "", parts[-1])
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", candidate):
            continue
        if _VISIBILITY_OR_MODIFIER_RE.fullmatch(candidate):
            continue
        state_vars.add(candidate)
    return state_vars


def _root_identifier(expr: str) -> str:
    match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", expr)
    return match.group(1) if match else ""


def _line_for_body(fn: FunctionSlice, offset: int) -> int:
    return fn.body_line + fn.body.count("\n", 0, max(offset, 0))


def _is_public_mutating(fn: FunctionSlice) -> bool:
    return bool(_EXTERNAL_OR_PUBLIC_RE.search(fn.header)) and not _VIEW_OR_PURE_RE.search(fn.header)


def _mutation_pattern(local: str) -> re.Pattern[str]:
    return re.compile(_MUTATION_RE_TEMPLATE.format(local=re.escape(local)), re.IGNORECASE | re.DOTALL)


def _canonical_no_ws(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _writeback_patterns(source_expr: str, local: str, access: str) -> tuple[str, ...]:
    src = re.escape(_canonical_no_ws(source_expr))
    loc = re.escape(_canonical_no_ws(local))
    patterns = [rf"{src}={loc};"]
    if access:
        acc = re.escape(_canonical_no_ws(access))
        patterns.extend(
            [
                rf"{src}{acc}=.+;",
                rf"{src}{acc}(?:\+=|-=|\*=|/=|%=|\+\+|--).+;",
                rf"{src}{acc}={loc}{acc};",
            ]
        )
    return tuple(patterns)


def _statement_is_writeback(statement: str, source_expr: str, local: str, access: str) -> bool:
    compact = _canonical_no_ws(statement)
    if any(re.search(pattern, compact) for pattern in _writeback_patterns(source_expr, local, access)):
        return True
    src = re.escape(_canonical_no_ws(source_expr))
    loc = re.escape(_canonical_no_ws(local))
    return bool(
        re.search(
            rf"{src}(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])="
            rf"{loc}(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\]);",
            compact,
        )
    )


def _has_writeback_before(function_text: str, source_expr: str, local: str, access: str, start: int, end: int) -> bool:
    compact = _canonical_no_ws(function_text[start:end])
    return any(re.search(pattern, compact) for pattern in _writeback_patterns(source_expr, local, access))


def _has_value_context(fn: FunctionSlice, copied_type: str, local: str, source_expr: str, access: str, expr: str) -> bool:
    haystack = " ".join([fn.name, copied_type, local, source_expr, access, expr])
    return bool(_VALUE_WORD_RE.search(haystack) or _ECONOMIC_FUNCTION_RE.search(fn.name))


def _sink_mentions_value(statement: str, local: str) -> bool:
    if re.search(rf"\b{re.escape(local)}\b", statement):
        return True
    return bool(_VALUE_WORD_RE.search(statement))


def _sink_branch(statement: str) -> str | None:
    if _TRANSFER_SINK_RE.fullmatch(statement.strip()):
        return "external-value-movement"
    if _FINALIZATION_SINK_RE.fullmatch(statement.strip()):
        return "state-finalization"
    if _ACCOUNTING_SINK_RE.fullmatch(statement.strip()):
        return "accounting-finalization"
    return None


def _iter_sink_statements(function_text: str, start: int):
    suffix = function_text[start:]
    matches: list[tuple[int, int, str]] = []
    for pattern in (_TRANSFER_SINK_RE, _FINALIZATION_SINK_RE, _ACCOUNTING_SINK_RE):
        for match in pattern.finditer(suffix):
            matches.append((start + match.start(), start + match.end(), match.group(0)))
    yield from sorted(matches, key=lambda item: item[0])


def _first_value_sink(
    function_text: str,
    start: int,
    local: str,
    source_expr: str,
    access: str,
) -> tuple[int, str, str] | None:
    candidates: list[tuple[int, int, str, str]] = []
    for sink_start, _sink_end, statement in _iter_sink_statements(function_text, start):
        if re.match(rf"(?is)\s*{re.escape(local)}\s*(?:\.|\[)", statement):
            continue
        if _statement_is_writeback(statement, source_expr, local, access):
            continue
        branch = _sink_branch(statement)
        if branch is None:
            continue
        if branch == "external-value-movement" and not _sink_mentions_value(statement, local):
            continue
        if branch == "accounting-finalization" and not _sink_mentions_value(statement, local):
            continue
        if _has_writeback_before(function_text, source_expr, local, access, start, sink_start):
            continue
        priority = {
            "external-value-movement": 0,
            "state-finalization": 1,
            "accounting-finalization": 2,
        }[branch]
        candidates.append((priority, sink_start, branch, statement.strip()))
    if not candidates:
        return None
    _priority, sink_start, branch, statement = sorted(candidates, key=lambda item: (item[0], item[1]))[0]
    return sink_start, branch, statement
    return None


def _copy_shape(copied_type: str, access: str) -> str:
    if "[]" in copied_type or access.strip().startswith("["):
        return "array-element"
    return "struct-element"


def _find_copy_mutations(fn: FunctionSlice, state_vars: set[str]) -> list[CopyMutation]:
    findings: list[CopyMutation] = []
    if not _is_public_mutating(fn):
        return findings
    seen: set[tuple[str, str, str]] = set()
    for copy_match in _MEMORY_COPY_RE.finditer(fn.body):
        copied_type = copy_match.group("type").strip()
        local = copy_match.group("local")
        source_expr = copy_match.group("src").strip()
        source_root = _root_identifier(source_expr)
        if source_root not in state_vars:
            continue
        if "[" not in source_expr and "." not in source_expr and "[]" not in copied_type:
            continue

        for mutation in _mutation_pattern(local).finditer(fn.body, copy_match.end()):
            access = (mutation.group("access") or "").strip()
            expr = (mutation.group("expr") or "").strip()
            if not _has_value_context(fn, copied_type, local, source_expr, access, expr):
                continue
            sink = _first_value_sink(fn.body, mutation.end(), local, source_expr, access)
            if sink is None:
                continue
            sink_start, sink_branch, statement = sink
            if _has_writeback_before(fn.body, source_expr, local, access, mutation.end(), sink_start):
                continue
            branch = f"{_copy_shape(copied_type, access)}:{sink_branch}"
            key = (local, source_expr, branch)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                CopyMutation(
                    local=local,
                    source_expr=source_expr,
                    access=access,
                    copied_type=copied_type,
                    line=_line_for_body(fn, mutation.start()),
                    branch=branch,
                    sink=statement,
                )
            )
            break
    return findings


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    """Regex scanner used by tests and recall tooling."""
    text = _strip_comments_and_strings(source)
    state_vars = _extract_state_vars(text)
    findings: list[Finding] = []
    if not state_vars:
        return findings

    for fn in _split_functions(text):
        for mutation in _find_copy_mutations(fn, state_vars):
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=mutation.line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    local=mutation.local,
                    source_expr=mutation.source_expr,
                    branch=mutation.branch,
                    message=(
                        f"{DETECTOR_NAME}: {mutation.branch} in `{fn.name}` copies "
                        f"`{mutation.source_expr}` into memory local `{mutation.local}`, "
                        f"mutates `{mutation.local}{mutation.access}` in value math, "
                        "and reaches a transfer, settlement, finalization, or "
                        "value-bearing accounting sink before an exact storage "
                        "writeback. NOT_SUBMIT_READY: detector fixture smoke "
                        "evidence only."
                    ),
                )
            )
    return findings


def _source_text(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _source_file(obj) -> str:
    try:
        filename = obj.source_mapping.filename
        for attr in ("absolute", "relative", "short"):
            value = getattr(filename, attr, None)
            if value:
                return str(value)
    except Exception:
        pass
    return "<unknown>"


class FundLossMemoryWritebackFire35(AbstractDetector):
    ARGUMENT = DETECTOR_NAME
    HELP = (
        "Storage struct or array element is copied to memory, mutated in "
        "value math, and a value-bearing sink fires before writeback."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Memory copy value mutation is not written back before funds move"
    WIKI_DESCRIPTION = (
        "Solidity copies storage structs and arrays into memory when assigned "
        "to a memory local. Mutating the local does not update storage. In "
        "fee, share, debt, collateral, or withdrawal paths, a transfer or "
        "finalization step can consume the assumed mutation while the canonical "
        "storage slot remains unchanged."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A withdrawal loads `Position memory p = positions[user]`, subtracts "
        "collateral from `p.collateral`, transfers collateral to the user, and "
        "marks the withdrawal finalized without `positions[user] = p`. The "
        "user receives assets while the stored collateral balance is unchanged."
    )
    WIKI_RECOMMENDATION = (
        "Use a storage reference for in-place mutations or write the mutated "
        "memory value back to the exact storage slot before any transfer, "
        "mint, burn, settlement, finalization, or downstream accounting write."
    )

    SUBMISSION_POSTURE = SUBMISSION_POSTURE
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self):
        results = []
        for contract in getattr(self, "contracts", []):
            contract_source = _source_text(contract)
            if not contract_source:
                continue
            functions_by_name = {
                str(getattr(function, "name", "") or ""): function
                for function in getattr(contract, "functions_and_modifiers_declared", [])
            }
            for finding in scan(contract_source, _source_file(contract)):
                anchor = functions_by_name.get(finding.function or "") or contract
                info = [anchor, f" - {finding.message} (line {finding.line})"]
                results.append(self.generate_result(info))
        return results


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "FundLossMemoryWritebackFire35",
    "scan",
]
