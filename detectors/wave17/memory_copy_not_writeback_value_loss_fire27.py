"""
memory-copy-not-writeback-value-loss-fire27

Fire27 Solidity lift for fund-loss-via-arithmetic misses where a storage
struct, array, or mapping entry is copied into memory, the local copy is
mutated in an accounting path, and the local copy is never assigned back to
the source storage slot.

This detector is candidate evidence only. It is NOT_SUBMIT_READY and cannot be
cited as exploit proof without a real in-scope path, negative control, and
R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path as _Path
from typing import Iterable

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

try:
    from _template_utils import is_vendored_or_test_contract, is_leaf_helper
except Exception:  # pragma: no cover - direct regex tests do not need helpers.
    def is_vendored_or_test_contract(_contract) -> bool:
        return False

    def is_leaf_helper(_function) -> bool:
        return False

try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
except Exception:  # pragma: no cover - regex runner can run without slither.
    class AbstractDetector:  # type: ignore[no-redef]
        pass

    class DetectorClassification:  # type: ignore[no-redef]
        MEDIUM = "Medium"
        LOW = "Low"


DETECTOR_NAME = "memory-copy-not-writeback-value-loss-fire27"
DETECTOR_SEVERITY_DEFAULT = "Medium"

_FUNCTION_START_RE = re.compile(
    r"(?is)\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\([^)]*\)(?P<trailer>[^{;]*)\{"
)
_TYPE_BLOCK_START_RE = re.compile(r"(?is)\b(?:struct|enum)\s+[A-Za-z_][A-Za-z0-9_]*[^{;]*\{")
_MEMORY_COPY_RE = re.compile(
    r"(?is)\b(?P<type>[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]*\])*)\s+"
    r"memory\s+(?P<local>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<src>[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:\[[^\]]+\]|\.[A-Za-z_][A-Za-z0-9_]*))*)\s*;"
)
_SKIP_NAME_RE = re.compile(r"(?i)(?:test|mock|fixture|harness|setup)")
_VIEW_OR_PURE_RE = re.compile(r"(?i)\b(?:view|pure)\b")
_MUTATING_HEADER_RE = re.compile(r"(?i)\b(?:external|public|internal)\b")
_ECONOMIC_ENTRY_RE = re.compile(
    r"(?i)^(?:deposit|withdraw|redeem|mint|burn|claim|settle|payout|"
    r"collect|liquidate|borrow|repay|swap|trade|buy|sell|quote|preview|"
    r"convert|request|queue|process|finalize|draw|resolve|accrue|update|"
    r"distribute|harvest|allocate|apply|credit|debit|increase|decrease)"
)
_ACCOUNTING_WORD_RE = re.compile(
    r"(?i)(?:value|amount|asset|assets|share|shares|balance|balances|debt|"
    r"borrow|supply|collateral|credit|debit|fee|fees|reward|rewards|claim|"
    r"claimable|payout|reserve|reserves|liquidity|principal|account|"
    r"position|owed|total|rate|index|nav|vault|settlement)"
)
_ASSUMED_UPDATED_RE = re.compile(
    r"(?is)(?:"
    r"\bemit\b|"
    r"\breturn\b|"
    r"\b(?:transfer|safeTransfer|transferFrom|safeTransferFrom|_?mint|_?burn)\s*\(|"
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:total|Total|balance|Balance|debt|Debt|"
    r"asset|Asset|share|Share|reward|Reward|claim|Claim|reserve|Reserve|"
    r"liquidity|Liquidity|credit|Credit|debit|Debit)[A-Za-z0-9_]*"
    r"(?:\s*\[[^\]]+\])?\s*(?:=|\+=|-=)"
    r")"
)
_STATEMENT_SKIP_RE = re.compile(
    r"(?i)^\s*(?:pragma|import|using|event|error|modifier|constructor|"
    r"contract|interface|library|struct|enum)\b"
)
_VISIBILITY_OR_MODIFIER_RE = re.compile(
    r"(?i)\b(?:public|private|internal|external|constant|immutable|override)\b"
)


@dataclass(frozen=True)
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: str | None = None


@dataclass(frozen=True)
class _FunctionSource:
    name: str
    trailer: str
    start: int
    end: int
    text: str


@dataclass(frozen=True)
class _CopyFinding:
    local: str
    source_expr: str
    source_root: str
    copied_type: str
    offset: int
    branch: str


def _source_text(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _blank_match(match: re.Match[str]) -> str:
    return re.sub(r"[^\r\n]", " ", match.group(0))


def _strip_comments(source: str) -> str:
    text = re.sub(r"/\*.*?\*/", _blank_match, source, flags=re.DOTALL)
    return re.sub(r"//[^\n\r]*", _blank_match, text)


def _line_for(source: str, offset: int) -> int:
    return source.count("\n", 0, max(offset, 0)) + 1


def _find_matching_brace(source: str, open_brace: int) -> int | None:
    depth = 0
    for index in range(open_brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def _iter_functions(source: str) -> Iterable[_FunctionSource]:
    for match in _FUNCTION_START_RE.finditer(source):
        open_brace = source.find("{", match.start())
        if open_brace == -1:
            continue
        end = _find_matching_brace(source, open_brace)
        if end is None:
            continue
        yield _FunctionSource(
            name=match.group("name"),
            trailer=match.group("trailer") or "",
            start=match.start(),
            end=end,
            text=source[match.start():end],
        )


def _blank_balanced_blocks(source: str, start_re: re.Pattern[str]) -> str:
    chars = list(source)
    for match in start_re.finditer(source):
        open_brace = source.find("{", match.start())
        if open_brace == -1:
            continue
        end = _find_matching_brace(source, open_brace)
        if end is None:
            continue
        for index in range(match.start(), end):
            if chars[index] not in "\r\n":
                chars[index] = " "
    return "".join(chars)


def _declaration_surface(source: str) -> str:
    text = _blank_balanced_blocks(source, _FUNCTION_START_RE)
    text = _blank_balanced_blocks(text, _TYPE_BLOCK_START_RE)
    return text


def _root_identifier(expr: str) -> str:
    match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", expr)
    return match.group(1) if match else ""


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
        candidate = parts[-1]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", candidate):
            continue
        if _VISIBILITY_OR_MODIFIER_RE.fullmatch(candidate):
            continue
        state_vars.add(candidate)
    return state_vars


def _mutation_pattern(local: str) -> re.Pattern[str]:
    escaped = re.escape(local)
    return re.compile(
        rf"(?is)(?:"
        rf"\b{escaped}\s*(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])+"
        rf"\s*(?:[+\-*/%|&^]?=|\+\+|--)|"
        rf"\bdelete\s+{escaped}\s*(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])+"
        rf")"
    )


def _canonical_no_ws(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _has_direct_writeback(function_text: str, source_expr: str, local: str, mutation_end: int) -> bool:
    suffix = function_text[mutation_end:]
    compact = _canonical_no_ws(suffix)
    source_compact = _canonical_no_ws(source_expr)
    local_compact = _canonical_no_ws(local)
    if f"{source_compact}={local_compact};" in compact:
        return True
    return False


def _has_accounting_context(fn: _FunctionSource, copied_type: str, local: str, source_expr: str, mutation_text: str) -> bool:
    haystack = " ".join([fn.name, copied_type, local, source_expr, mutation_text])
    if _ACCOUNTING_WORD_RE.search(haystack):
        return True
    if _ECONOMIC_ENTRY_RE.search(fn.name):
        return True
    return False


def _assumes_updated(function_text: str, mutation_end: int, local: str) -> bool:
    suffix = function_text[mutation_end:mutation_end + 900]
    if _ASSUMED_UPDATED_RE.search(suffix):
        return True
    escaped = re.escape(local)
    return bool(re.search(rf"(?is)\b(?:emit|return)\b[^;]{{0,240}}\b{escaped}\b", suffix))


def _is_candidate_function(fn: _FunctionSource) -> bool:
    if _SKIP_NAME_RE.search(fn.name):
        return False
    if not _MUTATING_HEADER_RE.search(fn.trailer):
        return False
    if _VIEW_OR_PURE_RE.search(fn.trailer):
        return False
    return True


def _find_copy_losses(fn: _FunctionSource, state_vars: set[str]) -> list[_CopyFinding]:
    findings: list[_CopyFinding] = []
    if not _is_candidate_function(fn):
        return findings
    for copy_match in _MEMORY_COPY_RE.finditer(fn.text):
        copied_type = copy_match.group("type").strip()
        local = copy_match.group("local")
        source_expr = copy_match.group("src").strip()
        source_root = _root_identifier(source_expr)
        if source_root not in state_vars:
            continue

        mutation = _mutation_pattern(local).search(fn.text, copy_match.end())
        if mutation is None:
            continue
        mutation_text = mutation.group(0)
        if not _has_accounting_context(fn, copied_type, local, source_expr, mutation_text):
            continue
        if _has_direct_writeback(fn.text, source_expr, local, mutation.end()):
            continue
        if not _assumes_updated(fn.text, mutation.end(), local):
            continue

        branch = "array-copy" if "[" in copied_type or re.search(r"\[[^\]]+\]", mutation_text) else "struct-copy"
        findings.append(
            _CopyFinding(
                local=local,
                source_expr=source_expr,
                source_root=source_root,
                copied_type=copied_type,
                offset=copy_match.start() + mutation.start() - copy_match.end(),
                branch=branch,
            )
        )
    return findings


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    text = _strip_comments(source)
    state_vars = _extract_state_vars(text)
    findings: list[Finding] = []
    if not state_vars:
        return findings
    for fn in _iter_functions(text):
        for copy_loss in _find_copy_losses(fn, state_vars):
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(source, fn.start + copy_loss.offset),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"{DETECTOR_NAME}: branch {copy_loss.branch}: "
                        f"`{copy_loss.source_expr}` is copied into memory local "
                        f"`{copy_loss.local}`, mutated in an accounting context, "
                        "and not assigned back to the storage source before the "
                        "function assumes the value is updated. NOT_SUBMIT_READY: "
                        "detector fixture smoke evidence only."
                    ),
                )
            )
    return findings


class MemoryCopyNotWritebackValueLossFire27(AbstractDetector):
    ARGUMENT = DETECTOR_NAME
    HELP = (
        "Flags storage-to-memory struct or array copies that are mutated in "
        "accounting paths without a later explicit writeback to the source slot."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Memory copy mutated without storage writeback"
    WIKI_DESCRIPTION = (
        "A Solidity assignment from storage to memory copies the value. Mutating "
        "the local memory copy does not update storage. In balance, debt, reward, "
        "or reserve accounting paths, this can make later state and events assume "
        "a value changed even though the canonical storage slot did not."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A contract loads `Position memory p = positions[user]`, increments "
        "`p.debt`, updates `totalDebt`, and emits the new debt but never performs "
        "`positions[user] = p`. The aggregate and per-user debt diverge."
    )
    WIKI_RECOMMENDATION = (
        "Use a `storage` reference when mutating state in place, or explicitly "
        "assign the mutated memory copy back to the exact storage slot before "
        "using the value as persisted accounting state."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_source = _source_text(contract)
            if not contract_source:
                continue
            for finding in scan(contract_source, getattr(contract, "source_mapping", None).filename.short if getattr(contract, "source_mapping", None) else "<unknown>"):
                if not finding.function:
                    continue
                function_obj = None
                for function in contract.functions_and_modifiers_declared:
                    if getattr(function, "name", "") == finding.function:
                        function_obj = function
                        break
                if function_obj is not None and is_leaf_helper(function_obj):
                    continue
                info = [
                    function_obj or contract,
                    f" - {finding.message}",
                ]
                results.append(self.generate_result(info))
        return results


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "MemoryCopyNotWritebackValueLossFire27",
    "scan",
]
