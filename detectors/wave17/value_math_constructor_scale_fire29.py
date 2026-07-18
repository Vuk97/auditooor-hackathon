"""
value-math-constructor-scale-fire29

Flags Solidity contracts that derive a persistent scale, precision, ratio, or
rate slot in a constructor or initializer with unsafe value math, then consume
that slot in a later public economic path.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:1fbd7a4998da1f42
- context_pack_hash: 1fbd7a4998da1f424cce0858c69a5dd246edb458f1cb9f1927dd25e36d73cb98
- source ref: reference/patterns.dsl/fund-loss-via-arithmetic-value-math.yaml
- source ref: reference/poc_templates/arithmetic-underflow.t.sol.template
- source ref: reference/patterns.dsl.r76_glider/glider-incorrect-self-referencing-compound-arithmetic-py.yaml
- attack_class: fund-loss-via-arithmetic

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path as _Path
from typing import Iterable

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
except Exception:  # pragma: no cover - scan() remains usable without slither.
    class AbstractDetector:  # type: ignore[no-redef]
        pass

    class DetectorClassification:  # type: ignore[no-redef]
        HIGH = "High"
        MEDIUM = "Medium"


DETECTOR_NAME = "value-math-constructor-scale-fire29"
DETECTOR_SEVERITY_DEFAULT = "High"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"


@dataclass(frozen=True)
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: str | None = None
    initializer: str | None = None
    slot: str | None = None


@dataclass(frozen=True)
class _CallableSource:
    kind: str
    name: str
    trailer: str
    start: int
    body_start: int
    end: int
    text: str
    body: str


@dataclass(frozen=True)
class _ScaleAssignment:
    slot: str
    offset: int
    op: str
    expr: str
    branch: str


@dataclass(frozen=True)
class _DownstreamUse:
    function: str
    offset: int
    branch: str


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_CALLABLE_START_RE = re.compile(
    r"(?is)\b(?:(?P<ctor>constructor)\s*\([^;{}]*\)(?P<ctor_trailer>[^{};]*)\{|"
    r"function\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)"
    r"(?P<trailer>[^{};]*)\{)"
)
_STATE_DECL_RE = re.compile(
    r"(?m)^\s*(?:u?int(?:\d+)?)\s+"
    r"(?:(?:public|private|internal|constant|immutable|override)\s+)*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)"
)
_SCALE_SLOT_RE = re.compile(
    r"(?i)(?:scale|precision|ratio|rate|factor|multiplier|denominator|denom|decimal|wad|ray)"
)
_INIT_NAME_RE = re.compile(r"(?i)^(?:constructor|initialize\w*|init|__\w+_init|__init|setup|configure)$")
_VISIBILITY_RE = re.compile(r"(?i)\b(?:external|public)\b")
_VIEW_OR_PURE_RE = re.compile(r"(?i)\b(?:view|pure)\b")
_ECONOMIC_ENTRY_RE = re.compile(
    r"(?i)^(?:deposit|mint|withdraw|redeem|burn|claim|settle|payout|collect|"
    r"harvest|liquidate|borrow|repay|swap|trade|buy|sell|queue|request|"
    r"process|finalize|convert|preview|quote|accrue|update|distribute|fee)"
)
_VALUE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:asset|assets|share|shares|amount|amountOut|deposit|withdraw|"
    r"redeem|claim|payout|settle|fee|fees|price|rate|ratio|scale|precision|"
    r"value|credit|debt|collateral|reserve|reserves|supply|totalSupply|"
    r"totalAssets|balance|balances|minted|burned|owed)\b"
)
_VALUE_EFFECT_RE = re.compile(
    r"(?is)(?:safeTransferFrom|safeTransfer|transferFrom|transfer\s*\(|"
    r"_mint\s*\(|_burn\s*\(|mint\s*\(|burn\s*\(|"
    r"\b(?:balance|balances|share|shares|totalShares|totalAssets|totalSupply|"
    r"claimable|pending|fee|fees|debt|credit|credits|reserve|reserves|"
    r"settlement|owed|withdrawable)[A-Za-z0-9_]*(?:\s*\[[^\]]+\])?\s*(?:=|\+=|-=))"
)
_SAFE_MATH_RE = re.compile(
    r"(?is)\b(?:mulDiv|FullMath|FixedPointMathLib|PRBMath|wadMul|wadDiv|"
    r"rayMul|rayDiv|mulWad|divWad|normalizeDecimals|scaleByDecimals|"
    r"convertDecimals|Math\s*\.\s*mulDiv)\b"
)
_DECIMAL_EXPONENT_SUB_RE = re.compile(
    r"(?is)10\s*\*\*\s*(?:u?int(?:8|16|32|64|128|256)?\s*\(\s*)?\(?\s*"
    r"(?:18\s*-\s*[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*\s*-\s*18)"
)
_DECIMAL_VAR_RE = re.compile(
    r"(?is)18\s*-\s*(?:u?int(?:8|16|32|64|128|256)?\s*\(\s*)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_DIVISION_RE = re.compile(r"/")
_ARITH_RE = re.compile(r"(?:\+|-|\*|/|%)")


def _blank_match(match: re.Match[str]) -> str:
    text = match.group(0)
    return "\n" * text.count("\n") if "\n" in text else " "


def _strip_comments_and_strings(source: str) -> str:
    return _COMMENT_OR_STRING_RE.sub(_blank_match, source or "")


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


def _iter_callables(source: str) -> list[_CallableSource]:
    out: list[_CallableSource] = []
    for match in _CALLABLE_START_RE.finditer(source):
        open_brace = source.find("{", match.start())
        if open_brace < 0:
            continue
        end = _find_matching_brace(source, open_brace)
        if end is None:
            continue
        is_ctor = bool(match.group("ctor"))
        name = "constructor" if is_ctor else (match.group("name") or "")
        trailer = match.group("ctor_trailer") if is_ctor else match.group("trailer")
        out.append(
            _CallableSource(
                kind="constructor" if is_ctor else "function",
                name=name,
                trailer=trailer or "",
                start=match.start(),
                body_start=open_brace + 1,
                end=end,
                text=source[match.start():end],
                body=source[open_brace + 1:end - 1],
            )
        )
    return out


def _mask_ranges(source: str, ranges: Iterable[tuple[int, int]]) -> str:
    chars = list(source)
    for start, end in ranges:
        for index in range(max(start, 0), min(end, len(chars))):
            if chars[index] not in "\r\n":
                chars[index] = " "
    return "".join(chars)


def _scale_state_slots(source: str, callables: list[_CallableSource]) -> set[str]:
    masked = _mask_ranges(source, ((fn.start, fn.end) for fn in callables))
    return {
        match.group("name")
        for match in _STATE_DECL_RE.finditer(masked)
        if _SCALE_SLOT_RE.search(match.group("name"))
    }


def _assignment_pattern(slot: str) -> re.Pattern[str]:
    escaped = re.escape(slot)
    return re.compile(
        rf"(?is)\b{escaped}\b\s*(?P<op>\+=|-=|\*=|/=|=)\s*(?P<expr>[^;{{}}]+)\s*;"
    )


def _decimal_vars(expr: str) -> set[str]:
    out: set[str] = set()
    for match in _DECIMAL_VAR_RE.finditer(expr):
        name = match.group("name")
        if not name.lower().startswith("uint"):
            out.add(name)
    return out


def _has_slot_postcheck(body: str, slot: str) -> bool:
    escaped = re.escape(slot)
    patterns = [
        rf"(?is)\brequire\s*\([^;{{}}]*\b{escaped}\b\s*(?:>|>=|!=)\s*0",
        rf"(?is)\brequire\s*\([^;{{}}]*0\s*(?:<|<=|!=)\s*\b{escaped}\b",
        rf"(?is)\bif\s*\([^;{{}}]*\b{escaped}\b\s*==\s*0[^;{{}}]*\)\s*revert",
        rf"(?is)\bif\s*\([^;{{}}]*0\s*==\s*\b{escaped}\b[^;{{}}]*\)\s*revert",
        rf"(?is)\bif\s*\([^;{{}}]*\b{escaped}\b\s*<\s*1[^;{{}}]*\)\s*revert",
        rf"(?is)(?:ScaleZero|PrecisionZero|RatioZero|RateZero|ZeroScale|ZeroPrecision)",
    ]
    return any(re.search(pattern, body) for pattern in patterns)


def _has_decimal_bound(body: str, name: str) -> bool:
    escaped = re.escape(name)
    patterns = [
        rf"(?is)\brequire\s*\([^;{{}}]*\b{escaped}\b\s*<=\s*18",
        rf"(?is)\brequire\s*\([^;{{}}]*18\s*>=\s*\b{escaped}\b",
        rf"(?is)\bif\s*\([^;{{}}]*\b{escaped}\b\s*>\s*18[^;{{}}]*\)\s*revert",
        rf"(?is)\bUnsupportedDecimals\b|\bDecimalsTooHigh\b",
    ]
    return any(re.search(pattern, body) for pattern in patterns)


def _has_safety_postcheck(body: str, slot: str, expr: str) -> bool:
    if _has_slot_postcheck(body, slot):
        return True
    if _DECIMAL_EXPONENT_SUB_RE.search(expr):
        vars_seen = _decimal_vars(expr)
        if vars_seen and all(_has_decimal_bound(body, var) for var in vars_seen):
            return True
    return False


def _unsafe_assignment_branch(slot: str, op: str, expr: str) -> str | None:
    if _SAFE_MATH_RE.search(expr):
        return None
    if op != "=":
        if re.search(rf"(?is)\b{re.escape(slot)}\b", expr) or _VALUE_CONTEXT_RE.search(expr):
            return "compound-init-scale-arithmetic"
    if _DECIMAL_EXPONENT_SUB_RE.search(expr):
        return "constructor-decimal-exponent-scale"
    if _DIVISION_RE.search(expr) and (_VALUE_CONTEXT_RE.search(expr) or _SCALE_SLOT_RE.search(slot)):
        return "constructor-ratio-division-scale"
    if re.search(r"(?is)\b(?:1e\d+|10\s*\*\*\s*\d{1,2})\s*/", expr):
        return "constructor-fixed-point-division-scale"
    return None


def _is_initializer(fn: _CallableSource) -> bool:
    return bool(_INIT_NAME_RE.match(fn.name))


def _is_downstream_candidate(fn: _CallableSource) -> bool:
    if _is_initializer(fn):
        return False
    if not _VISIBILITY_RE.search(fn.trailer):
        return False
    if _VIEW_OR_PURE_RE.search(fn.trailer):
        return False
    if _ECONOMIC_ENTRY_RE.search(fn.name):
        return True
    return bool(_VALUE_CONTEXT_RE.search(fn.text) and _VALUE_EFFECT_RE.search(fn.text))


def _uses_slot_in_value_math(body: str, slot: str) -> bool:
    escaped = re.escape(slot)
    if not re.search(rf"(?is)\b{escaped}\b", body):
        return False
    if re.search(rf"(?is)\b{escaped}\b\s*(?:\*|/)|(?:\*|/)\s*\b{escaped}\b", body):
        return True
    if re.search(rf"(?is)\b(?:mulDiv|wadMul|wadDiv|rayMul|rayDiv)\s*\([^;{{}}]*\b{escaped}\b", body):
        return True
    return False


def _find_downstream_use(functions: list[_CallableSource], slot: str) -> _DownstreamUse | None:
    for fn in functions:
        if not _is_downstream_candidate(fn):
            continue
        if not _uses_slot_in_value_math(fn.body, slot):
            continue
        if not (_VALUE_CONTEXT_RE.search(fn.body) and _VALUE_EFFECT_RE.search(fn.body)):
            continue
        match = re.search(rf"(?is)\b{re.escape(slot)}\b", fn.body)
        return _DownstreamUse(
            function=fn.name,
            offset=fn.body_start + (match.start() if match else 0),
            branch="downstream-economic-scale-consumption",
        )
    return None


def _find_unsafe_scale_assignments(fn: _CallableSource, slots: set[str]) -> list[_ScaleAssignment]:
    if not _is_initializer(fn):
        return []
    findings: list[_ScaleAssignment] = []
    for slot in sorted(slots):
        for match in _assignment_pattern(slot).finditer(fn.body):
            expr = (match.group("expr") or "").strip()
            op = match.group("op") or "="
            branch = _unsafe_assignment_branch(slot, op, expr)
            if branch is None:
                continue
            if _has_safety_postcheck(fn.body, slot, expr):
                continue
            findings.append(
                _ScaleAssignment(
                    slot=slot,
                    offset=fn.body_start + match.start(),
                    op=op,
                    expr=expr,
                    branch=branch,
                )
            )
            break
    return findings


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    """Regex scanner used by tests and recall tooling."""
    text = _strip_comments_and_strings(source)
    functions = _iter_callables(text)
    slots = _scale_state_slots(text, functions)
    if not slots:
        return []

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for fn in functions:
        for assignment in _find_unsafe_scale_assignments(fn, slots):
            downstream = _find_downstream_use(functions, assignment.slot)
            if downstream is None:
                continue
            key = (assignment.slot, downstream.function)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(text, assignment.offset),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=downstream.function,
                    initializer=fn.name,
                    slot=assignment.slot,
                    message=(
                        f"{DETECTOR_NAME}: {assignment.branch} assigns "
                        f"`{assignment.slot}` in {fn.name} without a scale postcheck; "
                        f"{downstream.function} later consumes it in value-moving math. "
                        "NOT_SUBMIT_READY: detector fixture smoke evidence only."
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


class ValueMathConstructorScaleFire29(AbstractDetector):
    ARGUMENT = DETECTOR_NAME
    HELP = (
        "Constructor or initializer derives a persistent scale, precision, "
        "ratio, or rate with unsafe value math, then a deposit, withdrawal, "
        "accounting, or fee path consumes that bad scale."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Unsafe constructor scale math can misprice later value movement"
    WIKI_DESCRIPTION = (
        "Scale constants derived during construction or initialization can "
        "truncate to zero, underflow decimal exponents, or compound stale "
        "state. If later value-moving functions trust that slot, deposits, "
        "withdrawals, accounting, or fee settlement can misprice funds."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A vault deploys with `shareScale = referenceShares / referenceAssets` "
        "and only checks that the inputs are non-zero. If the ratio truncates "
        "to zero or a decimal exponent is built from an unsupported token, "
        "later deposit or withdrawal accounting uses a broken scale."
    )
    WIKI_RECOMMENDATION = (
        "Use full-precision helpers, validate decimal bounds before exponent "
        "math, and require every derived scale or ratio to be positive before "
        "any value-moving path can consume it."
    )

    SUBMISSION_POSTURE = SUBMISSION_POSTURE
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
            functions_by_name = {
                str(getattr(function, "name", "") or ""): function
                for function in contract.functions_and_modifiers_declared
            }
            for finding in scan(contract_source, _source_file(contract)):
                anchor = functions_by_name.get(finding.function or "")
                if anchor is not None and is_leaf_helper(anchor):
                    continue
                info = [
                    anchor or contract,
                    (
                        f" - {finding.message} "
                        f"(line {finding.line})"
                    ),
                ]
                results.append(self.generate_result(info))
        return results


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "ValueMathConstructorScaleFire29",
    "scan",
]
