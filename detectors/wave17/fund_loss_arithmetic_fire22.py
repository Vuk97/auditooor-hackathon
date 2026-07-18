"""
fund-loss-arithmetic-fire22

Fire22 Solidity lift for the Glider self-referencing compound arithmetic
shape. It flags value-bearing state slots updated with compound assignment
where the right-hand side reads the same slot again, such as
`balanceOf[user] += balanceOf[user] + delta`.

This is distinct from Fire21 fund-loss arithmetic coverage, which covered
caller supplied value routes, duplicate factory registration, and unchecked
int128-to-uint128 casts.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path as _Path
from typing import Iterable

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


DETECTOR_NAME = "fund-loss-arithmetic-fire22"
DETECTOR_SEVERITY_DEFAULT = "Medium"

_VALUE_SLOT_RE = re.compile(
    r"(?i)(?:balance|balances|balanceOf|share|shares|credit|credits|"
    r"claimable|reward|rewards|fee|fees|liquidity|reserve|reserves|asset|"
    r"assets|debt|payout|principal|supply|totalSupply|totalAssets|"
    r"accrued|accumulator)"
)
_ECONOMIC_ENTRY_RE = re.compile(
    r"(?i)^(?:deposit|withdraw|mint|burn|claim|settle|payout|collect|"
    r"update|accrue|sync|rebalance|transfer|stake|unstake|borrow|repay|"
    r"liquidate|redeem)"
)
_SKIP_NAME_RE = re.compile(r"(?i)(?:test|mock|fixture|harness|setup|helper)")
_VISIBILITY_RE = re.compile(r"(?i)\b(?:external|public)\b")
_FUNCTION_START_RE = re.compile(
    r"(?is)\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\([^)]*\)(?P<trailer>[^{;]*)\{"
)
_STATE_DECL_RE = re.compile(
    r"(?m)^\s*(?:mapping\s*\([^;\n]+\)|u?int(?:\d+)?)\s+"
    r"(?:(?:public|private|internal|constant|immutable|override)\s+)*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;|\[)"
)


@dataclass(frozen=True)
class _FunctionSource:
    name: str
    trailer: str
    start: int
    end: int
    text: str


def _source_text(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _strip_comments(source: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"//[^\n\r]*", "", text)


def _visibility(function) -> str:
    return str(getattr(function, "visibility", "") or "").lower()


def _function_name(function) -> str:
    return str(getattr(function, "name", "") or "")


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


def _mask_ranges(source: str, ranges: Iterable[tuple[int, int]]) -> str:
    chars = list(source)
    for start, end in ranges:
        for index in range(max(start, 0), min(end, len(chars))):
            if chars[index] not in "\r\n":
                chars[index] = " "
    return "".join(chars)


def _state_value_slots(source: str) -> set[str]:
    functions = list(_iter_functions(source))
    masked = _mask_ranges(source, ((fn.start, fn.end) for fn in functions))
    return {
        match.group("name")
        for match in _STATE_DECL_RE.finditer(masked)
        if _VALUE_SLOT_RE.search(match.group("name"))
    }


def _compound_self_ref_pattern(slot: str) -> re.Pattern[str]:
    escaped = re.escape(slot)
    index = r"(?:\s*\[[^\]\n;{}]+\]){0,3}"
    return re.compile(
        rf"(?is)\b{escaped}\b{index}\s*(?P<op>\+=|-=|\*=|/=|%=)\s*"
        rf"(?P<rhs>[^;{{}}]*\b{escaped}\b{index}[^;{{}}]*)\s*;"
    )


def _is_candidate_function_name(name: str) -> bool:
    return bool(_ECONOMIC_ENTRY_RE.search(name)) and not _SKIP_NAME_RE.search(name)


def _state_variables_written(function) -> set[str]:
    names: set[str] = set()
    try:
        for state_var in getattr(function, "state_variables_written", []) or []:
            name = str(getattr(state_var, "name", "") or "")
            if name:
                names.add(name)
    except Exception:
        pass
    return names


def _find_self_ref_assignments(source: str, slots: Iterable[str]) -> list[tuple[str, str, int]]:
    findings: list[tuple[str, str, int]] = []
    seen: set[tuple[str, int]] = set()
    for slot in sorted(set(slots)):
        if not _VALUE_SLOT_RE.search(slot):
            continue
        for match in _compound_self_ref_pattern(slot).finditer(source):
            key = (slot, match.start())
            if key in seen:
                continue
            seen.add(key)
            findings.append((slot, match.group("op"), match.start()))
    return findings


def _regex_finding(source: str, file_path: str, offset: int, slot: str, op: str):
    return {
        "detector": DETECTOR_NAME,
        "severity": DETECTOR_SEVERITY_DEFAULT,
        "file": file_path,
        "line": _line_for(source, offset),
        "message": (
            f"{DETECTOR_NAME}: value-bearing state slot `{slot}` uses `{op}` "
            "while the right-hand side reads the same slot again. "
            "NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
        "function": None,
    }


def scan(source: str, file_path: str):
    """Regex-runner entrypoint for recall scoreboard integration."""
    text = _strip_comments(source)
    slots = _state_value_slots(text)
    if not slots:
        return []

    findings = []
    for function in _iter_functions(text):
        if not _VISIBILITY_RE.search(function.trailer):
            continue
        if not _is_candidate_function_name(function.name):
            continue
        for slot, op, relative_offset in _find_self_ref_assignments(function.text, slots):
            findings.append(
                _regex_finding(
                    source,
                    file_path,
                    function.start + relative_offset,
                    slot,
                    op,
                )
            )
    return findings


class FundLossArithmeticFire22(AbstractDetector):
    ARGUMENT = DETECTOR_NAME
    HELP = "Flags value-bearing state slots with self-referencing compound arithmetic"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Fund-loss arithmetic via self-referencing compound update"
    WIKI_DESCRIPTION = (
        "A balance, share, credit, reward, fee, or asset accumulator should add "
        "only the intended delta. Compound assignment that also rereads the "
        "same slot on the right-hand side can double count the existing value."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A deposit or claim path intends to add `delta`, but uses "
        "`balanceOf[user] += balanceOf[user] + delta`. Every call compounds the "
        "old balance into the new credit and can inflate withdrawable value."
    )
    WIKI_RECOMMENDATION = (
        "Compute the intended next value from stable operands and assign once, "
        "or use compound assignment only with a delta that does not read the "
        "same state slot."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_source = _strip_comments(_source_text(contract))
            if not re.search(r"(?is)(\+=|-=|\*=|/=|%=)", contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if getattr(function, "is_constructor", False):
                    continue
                name = _function_name(function)
                if not _is_candidate_function_name(name):
                    continue
                if _visibility(function) not in {"external", "public"}:
                    continue
                if is_leaf_helper(function):
                    continue

                source = _strip_comments(_source_text(function))
                if not source:
                    continue
                written_slots = {
                    slot for slot in _state_variables_written(function) if _VALUE_SLOT_RE.search(slot)
                }
                if not written_slots:
                    continue

                for slot, op, _offset in _find_self_ref_assignments(source, written_slots):
                    info = [
                        function,
                        (
                            " - fund-loss-arithmetic-fire22: value-bearing "
                            f"state slot `{slot}` uses `{op}` while the "
                            "right-hand side reads the same slot again. "
                            "NOT_SUBMIT_READY: detector fixture smoke evidence only."
                        ),
                    ]
                    results.append(self.generate_result(info))
        return results


__all__ = [
    "FundLossArithmeticFire22",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "scan",
]
