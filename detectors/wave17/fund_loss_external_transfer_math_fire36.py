"""
fund-loss-external-transfer-math-fire36

Solidity recall-lift detector for fund-loss-via-arithmetic variants where a
final amount is derived through lossy integer division, narrow casts, stale
rate or scale snapshots, or storage-to-memory value use before the amount is
consumed by a transfer, mint, burn, or debt-settlement sink.

This is intentionally narrower than generic arithmetic warnings. A returned
finding requires both a suspicious amount computation and a later value-moving
or debt-settlement use of the computed variable.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:a14a00fe6ae82f40
- context_pack_hash: a14a00fe6ae82f4042f8fce336676e437af06060e1f44425bad63447335cb2d7
- source ref: reports/detector_lift_fire35_20260605/post_priorities_all.md
- source ref: reference/patterns.dsl/fund-loss-via-arithmetic-value-math.yaml
- source ref: detectors/wave17/fund_loss_memory_writeback_fire35.py
- source ref: detectors/wave17/integer_clamp_fee_scale_fire34.py
- attack_class: fund-loss-via-arithmetic

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "fund-loss-external-transfer-math-fire36"
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
    amount_var: Optional[str] = None
    branch: Optional[str] = None
    sink: Optional[str] = None


@dataclass(frozen=True)
class FunctionSlice:
    name: str
    header: str
    body: str
    function_line: int
    body_line: int


@dataclass(frozen=True)
class AmountHazard:
    name: str
    expr: str
    line: int
    branch: str
    sink_kind: str
    sink: str


_SMALL_WIDTHS = (8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128)
_SMALL_UINT = r"uint(?:" + "|".join(str(width) for width in _SMALL_WIDTHS) + r")"

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
_TYPE_BLOCK_START_RE = re.compile(r"(?is)\b(?:struct|enum)\s+[A-Za-z_][A-Za-z0-9_]*[^{;]*\{")
_EXTERNAL_OR_PUBLIC_RE = re.compile(r"\b(?:external|public)\b")
_VIEW_OR_PURE_RE = re.compile(r"\b(?:view|pure)\b")
_STATEMENT_SKIP_RE = re.compile(
    r"(?i)^\s*(?:pragma|import|using|event|error|modifier|constructor|"
    r"contract|interface|library|struct|enum)\b"
)
_VISIBILITY_OR_MODIFIER_RE = re.compile(
    r"(?i)\b(?:public|private|internal|external|constant|immutable|override)\b"
)
_ASSIGNMENT_RE = re.compile(
    r"(?is)\b(?:(?P<decl>u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|256)?|uint|int)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>[^;{}]+?)\s*;"
)
_MEMORY_COPY_RE = re.compile(
    r"(?is)\b(?P<type>(?:(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"[A-Za-z_][A-Za-z0-9_]*)(?:\s*\[[^\]]*\])*)\s+memory\s+"
    r"(?P<local>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<src>[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:\[[^\]]+\]|\.[A-Za-z_][A-Za-z0-9_]*))*)\s*;"
)
_VALUE_NAME_RE = re.compile(
    r"(?i)(?:amount|asset|assets|share|shares|mint|minted|burn|burned|"
    r"out|output|payout|proceeds|fee|reward|claim|credit|debit|value|"
    r"collateral|debt|repay|owed|net|gross|token|tokens|receipt|liquidity|"
    r"principal|settle|settled|borrow|liability)"
)
_VALUE_EXPR_RE = re.compile(
    r"(?i)\b(?:amount|asset|assets|share|shares|supply|totalSupply|"
    r"totalAssets|balance|reserve|liquidity|price|oraclePrice|rawPrice|"
    r"answer|rate|ratio|index|scale|precision|fee|reward|payout|claim|"
    r"credit|debit|collateral|debt|exchangeRate|bps|basis|principal|"
    r"borrow|liability|settle|repay|vault|pool)\w*\b"
)
_ECONOMIC_FUNCTION_RE = re.compile(
    r"(?i)^(?:borrow|burn|claim|close|collect|complete|debit|deposit|"
    r"distribute|finalize|harvest|liquidate|mint|payout|redeem|release|"
    r"repay|settle|swap|trade|withdraw)"
)
_SAFE_MATH_RE = re.compile(
    r"(?is)\b(?:mulDiv|mulDivUp|FullMath|FixedPointMathLib|PRBMath|"
    r"Math\s*\.\s*mulDiv|wadMul|wadDiv|mulWad|divWad|mulWadDown|"
    r"divWadDown|mulWadUp|divWadUp|ceilDiv|roundUp|roundingUp|"
    r"Rounding\s*\.\s*(?:Up|Ceil)|normalizeDecimals|normaliseDecimals|"
    r"convertDecimals|scaleByDecimals)\b"
)
_SAFE_CAST_RE = re.compile(
    r"(?is)\b(?:SafeCast|SafeCastLib|CastLib|toUint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128)\s*\()"
)
_HARDCODED_SCALE_RE = re.compile(
    r"(?is)\b(?:1e6|1e8|1e18|1e27|10\s*\*\*\s*(?:6|8|18|27)|"
    r"1000000|100000000|1000000000000000000|WAD|RAY|BPS|BASIS_POINTS|"
    r"PRECISION|SCALE|SCALAR|DECIMALS)\b"
)
_DYNAMIC_DECIMALS_RE = re.compile(
    r"(?is)(?:\.\s*decimals\s*\(|IERC20Metadata|tokenDecimals|assetDecimals|"
    r"shareDecimals|feedDecimals|priceDecimals|oracleDecimals|normalize|"
    r"normalise|convertDecimals)"
)
_SCALE_NAME_RE = re.compile(r"(?i)(?:rate|scale|index|price|precision|exchangeRate|conversion)")
_REFRESH_RE = re.compile(r"(?is)\b(?:_?accrue|_?refresh|_?update|_?sync|_?recompute)[A-Za-z0-9_]*\s*\(")
_CURRENT_HELPER_RE = re.compile(r"(?is)\b(?:current|latest|fresh|preview|accrued|updated)[A-Za-z0-9_]*(?:Rate|Scale|Index|Price)\s*\(")
_SMALL_CAST_RE = re.compile(r"\b(?P<cast>" + _SMALL_UINT + r")\s*\(")


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


def _line_for_body(fn: FunctionSlice, offset: int) -> int:
    return fn.body_line + fn.body.count("\n", 0, max(offset, 0))


def _is_public_mutating(fn: FunctionSlice) -> bool:
    return bool(_EXTERNAL_OR_PUBLIC_RE.search(fn.header)) and not _VIEW_OR_PURE_RE.search(fn.header)


def _looks_value_amount(fn: FunctionSlice, name: str, expr: str) -> bool:
    return bool(
        _VALUE_NAME_RE.search(name)
        or _VALUE_EXPR_RE.search(expr)
        or _ECONOMIC_FUNCTION_RE.search(fn.name)
    )


def _identifiers(expr: str) -> set[str]:
    ignored = {
        "uint",
        "uint8",
        "uint16",
        "uint24",
        "uint32",
        "uint40",
        "uint48",
        "uint56",
        "uint64",
        "uint72",
        "uint80",
        "uint88",
        "uint96",
        "uint104",
        "uint112",
        "uint120",
        "uint128",
        "uint256",
        "int",
        "int256",
        "type",
    }
    return {
        token
        for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expr)
        if token not in ignored
    }


def _small_uint_width(name: str | None) -> int | None:
    if not name:
        return None
    match = re.search(r"\d+", name)
    if not match:
        return None
    width = int(match.group(0))
    return width if width in _SMALL_WIDTHS else None


def _cast_width(expr: str, decl: str | None) -> int | None:
    cast = _SMALL_CAST_RE.search(expr)
    if cast:
        return _small_uint_width(cast.group("cast"))
    return _small_uint_width(decl)


def _target_max_patterns(width: int) -> tuple[str, ...]:
    return (
        r"type\s*\(\s*uint" + str(width) + r"\s*\)\s*\.\s*max",
        r"MAX_UINT" + str(width),
        r"MAX_U" + str(width),
        r"2\s*\*\*\s*" + str(width),
        r"1\s*<<\s*" + str(width),
    )


def _has_pre_cast_bound(prefix: str, identifiers: set[str], width: int | None) -> bool:
    if width is None or not identifiers:
        return False
    window = prefix[-1800:]
    for ident in identifiers:
        ident_re = r"\b" + re.escape(ident) + r"\b"
        for bound in _target_max_patterns(width):
            bound_re = r"(?:" + bound + r")"
            patterns = (
                ident_re + r"[^;{}]{0,220}(?:<=|<)[^;{}]{0,140}" + bound_re,
                bound_re + r"[^;{}]{0,220}(?:>=|>)[^;{}]{0,140}" + ident_re,
                ident_re + r"[^;{}]{0,220}(?:>|>=)[^;{}]{0,140}" + bound_re,
            )
            for pattern in patterns:
                match = re.search(pattern, window, flags=re.I | re.S)
                if not match:
                    continue
                local = window[max(0, match.start() - 180): min(len(window), match.end() + 220)]
                if re.search(r"\b(?:require|assert|if)\b", local) and re.search(
                    r"\b(?:revert|return|Overflow|overflow|too large|require|assert)\b",
                    local,
                    re.I,
                ):
                    return True
    return False


def _has_division_before_multiplication(expr: str) -> bool:
    div_pos = expr.find("/")
    mul_pos = expr.find("*")
    return div_pos >= 0 and mul_pos >= 0 and div_pos < mul_pos


def _division_hazard(expr: str) -> bool:
    if "/" not in expr:
        return False
    if _SAFE_MATH_RE.search(expr):
        return False
    if _has_division_before_multiplication(expr):
        return True
    return bool(_HARDCODED_SCALE_RE.search(expr) or _VALUE_EXPR_RE.search(expr))


def _narrow_cast_hazard(expr: str, decl: str | None, prefix: str) -> bool:
    width = _cast_width(expr, decl)
    if width is None:
        return False
    if _SAFE_CAST_RE.search(expr):
        return False
    if _has_pre_cast_bound(prefix, _identifiers(expr), width):
        return False
    return bool("*" in expr or "/" in expr or _VALUE_EXPR_RE.search(expr))


def _snapshot_assignments(prefix: str) -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    for match in _ASSIGNMENT_RE.finditer(prefix):
        name = match.group("name")
        expr = match.group("expr").strip()
        if not _SCALE_NAME_RE.search(name):
            continue
        if _CURRENT_HELPER_RE.search(expr):
            continue
        if not (_SCALE_NAME_RE.search(expr) or _HARDCODED_SCALE_RE.search(expr)):
            continue
        out.append((match.start(), name, expr))
    return out


def _stale_scale_hazard(prefix: str, expr: str) -> bool:
    if _CURRENT_HELPER_RE.search(expr):
        return False
    identifiers = _identifiers(expr)
    for snapshot_start, snapshot_name, snapshot_expr in _snapshot_assignments(prefix):
        if snapshot_name not in identifiers:
            continue
        if _REFRESH_RE.search(prefix[:snapshot_start]):
            continue
        if _CURRENT_HELPER_RE.search(snapshot_expr):
            continue
        return True
    return False


def _canonical_no_ws(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _writeback_patterns(source_expr: str, local: str) -> tuple[str, ...]:
    src = re.escape(_canonical_no_ws(source_expr))
    loc = re.escape(_canonical_no_ws(local))
    return (
        rf"{src}={loc};",
        rf"{src}(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])={loc}(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\]);",
    )


def _has_writeback_before(function_text: str, source_expr: str, local: str, start: int, end: int) -> bool:
    compact = _canonical_no_ws(function_text[start:end])
    return any(re.search(pattern, compact) for pattern in _writeback_patterns(source_expr, local))


def _memory_locals(function_text: str, state_vars: set[str]) -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    for match in _MEMORY_COPY_RE.finditer(function_text):
        local = match.group("local")
        source_expr = match.group("src").strip()
        root = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", source_expr)
        if root is None or root.group(1) not in state_vars:
            continue
        if "[" not in source_expr and "." not in source_expr:
            continue
        out.append((match.start(), local, source_expr))
    return out


def _memory_writeback_hazard(function_text: str, expr: str, state_vars: set[str], assign_start: int, sink_start: int) -> bool:
    for copy_start, local, source_expr in _memory_locals(function_text[:assign_start], state_vars):
        if not re.search(r"\b" + re.escape(local) + r"\b", expr):
            continue
        if _has_writeback_before(function_text, source_expr, local, copy_start, sink_start):
            continue
        return True
    return False


def _call_with_var_pattern(names: str, amount_var: str) -> re.Pattern[str]:
    return re.compile(
        r"(?is)\b(?:" + names + r")\s*\([^;{}]*\b" + re.escape(amount_var) + r"\b[^;{}]*\)\s*;",
        re.I | re.S,
    )


def _debt_write_pattern(amount_var: str) -> re.Pattern[str]:
    return re.compile(
        r"(?is)(?<!\.)\b(?:debt|debts|borrow|borrows|principal|liability|liabilities|settled|repaid)"
        r"[A-Za-z0-9_]*(?:\s*\[[^\]]+\]\s*)?(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
        r"\s*(?:=|\+=|-=)[^;{}]*\b" + re.escape(amount_var) + r"\b[^;{}]*;",
        re.I | re.S,
    )


def _first_sink_after(function_text: str, amount_var: str, start: int) -> tuple[int, str, str] | None:
    suffix = function_text[start:]
    candidates: list[tuple[int, int, str, str]] = []
    transfer_names = (
        r"safeTransferFrom|safeTransfer|transferFrom|transfer|sendValue|"
        r"_mint|mint|_burn|burn"
    )
    debt_names = (
        r"settleDebt|repayDebt|closeDebt|recordDebt|bookDebt|debitDebt|"
        r"creditDebt|settle|repay|liquidate|accountDebt"
    )
    for match in _call_with_var_pattern(transfer_names, amount_var).finditer(suffix):
        candidates.append((start + match.start(), 0, "external-value-movement", match.group(0).strip()))
    for match in _call_with_var_pattern(debt_names, amount_var).finditer(suffix):
        candidates.append((start + match.start(), 1, "debt-settlement", match.group(0).strip()))
    for match in _debt_write_pattern(amount_var).finditer(suffix):
        candidates.append((start + match.start(), 1, "debt-settlement", match.group(0).strip()))
    if not candidates:
        return None
    sink_start, _priority, sink_kind, statement = sorted(candidates, key=lambda item: (item[0], item[1]))[0]
    return sink_start, sink_kind, statement


def _has_output_guard(function_text: str, amount_var: str, assign_end: int, sink_start: int) -> bool:
    escaped = re.escape(amount_var)
    window = function_text[assign_end:sink_start]
    patterns = (
        rf"(?is)\brequire\s*\([^;{{}}]*\b{escaped}\b\s*(?:>|>=|!=)\s*(?:0|1|min[A-Za-z0-9_]*|expected[A-Za-z0-9_]*)",
        rf"(?is)\brequire\s*\([^;{{}}]*(?:min[A-Za-z0-9_]*|expected[A-Za-z0-9_]*)\s*<=\s*\b{escaped}\b",
        rf"(?is)\bif\s*\([^;{{}}]*\b{escaped}\b\s*==\s*0[^;{{}}]*\)\s*revert",
        rf"(?is)\bif\s*\([^;{{}}]*\b{escaped}\b\s*<\s*(?:min[A-Za-z0-9_]*|expected[A-Za-z0-9_]*|1)[^;{{}}]*\)\s*revert",
        rf"(?is)\b(?:ZeroAmount|ZeroAssets|ZeroShares|Slippage|MinAmount|AmountTooSmall)\b",
    )
    return any(re.search(pattern, window) for pattern in patterns)


def _branch_for_assignment(
    fn: FunctionSlice,
    function_text: str,
    state_vars: set[str],
    match: re.Match[str],
    sink_start: int,
) -> str | None:
    name = match.group("name")
    expr = match.group("expr").strip()
    decl = match.group("decl")
    prefix = function_text[: match.start()]
    if not _looks_value_amount(fn, name, expr):
        return None
    if _has_output_guard(function_text, name, match.end(), sink_start):
        return None
    if _memory_writeback_hazard(function_text, expr, state_vars, match.start(), sink_start):
        return "memory-writeback-before-transfer-amount"
    if _stale_scale_hazard(prefix, expr):
        return "stale-scale-before-transfer-amount"
    if _narrow_cast_hazard(expr, decl, prefix):
        return "narrow-cast-before-transfer-amount"
    if _division_hazard(expr):
        return "lossy-division-before-transfer-amount"
    return None


def _amount_hazards(fn: FunctionSlice, state_vars: set[str]) -> list[AmountHazard]:
    if not _is_public_mutating(fn):
        return []
    out: list[AmountHazard] = []
    text = f"{fn.header}\n{fn.body}"
    seen: set[tuple[str, str, str]] = set()
    for match in _ASSIGNMENT_RE.finditer(text):
        amount_var = match.group("name")
        sink = _first_sink_after(text, amount_var, match.end())
        if sink is None:
            continue
        sink_start, sink_kind, sink_statement = sink
        branch = _branch_for_assignment(fn, text, state_vars, match, sink_start)
        if branch is None:
            continue
        if sink_kind == "debt-settlement":
            branch = branch.replace("transfer-amount", "debt-settlement")
        key = (amount_var, branch, sink_statement)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            AmountHazard(
                name=amount_var,
                expr=match.group("expr").strip(),
                line=fn.function_line + text.count("\n", 0, match.start()),
                branch=branch,
                sink_kind=sink_kind,
                sink=sink_statement,
            )
        )
    return out


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    """Regex scanner used by tests and recall tooling."""
    text = _strip_comments_and_strings(source)
    state_vars = _extract_state_vars(text)
    findings: list[Finding] = []

    for fn in _split_functions(text):
        for hazard in _amount_hazards(fn, state_vars):
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=hazard.line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    amount_var=hazard.name,
                    branch=hazard.branch,
                    sink=hazard.sink_kind,
                    message=(
                        f"{DETECTOR_NAME}: {hazard.branch} in `{fn.name}` computes "
                        f"`{hazard.name}` as `{hazard.expr}` and later consumes it "
                        f"via {hazard.sink_kind} sink `{hazard.sink}`. "
                        "Use full-precision math, pre-cast bounds, fresh rate or "
                        "scale reads, and exact storage writeback before transfer, "
                        "mint, burn, or debt settlement. NOT_SUBMIT_READY: detector "
                        "fixture smoke evidence only."
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


class FundLossExternalTransferMathFire36(AbstractDetector):
    ARGUMENT = DETECTOR_NAME
    HELP = (
        "Lossy amount math is consumed by transfer, mint, burn, or debt "
        "settlement."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "External transfer amount math can lose value before settlement"
    WIKI_DESCRIPTION = (
        "A final token movement or debt-settlement amount can be derived from "
        "integer division, a narrow integer cast, a stale rate or scale "
        "snapshot, or a storage-to-memory value that is not written back. If "
        "that amount is then transferred, minted, burned, or settled, the "
        "value movement can diverge from the protocol's intended accounting."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A withdrawal computes `assets = shares / totalShares * totalAssets` "
        "and transfers `assets`. Small share amounts round to zero before the "
        "pool asset multiplier is applied. Sibling variants narrow a computed "
        "burn amount before a burn, mint from a stale scale snapshot, or "
        "settle debt from a memory copy whose storage slot was not updated."
    )
    WIKI_RECOMMENDATION = (
        "Compute value-moving amounts with full precision, apply caps before "
        "casts, refresh rates or scales before pricing, and write mutated "
        "storage values back before any transfer, mint, burn, or settlement."
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
    "FundLossExternalTransferMathFire36",
    "SUBMISSION_POSTURE",
    "scan",
]
