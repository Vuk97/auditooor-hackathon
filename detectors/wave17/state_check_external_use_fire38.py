"""
state-check-external-use-fire38

Regex API detector for Solidity paymaster, hook, swap, and fee paths that
validate a sender, fee, balance, reserve, or invariant, cross an external call
or mutable state boundary, then use the stale checked value for final
acceptance without a post-boundary reload or revalidation.

Source refs:
- reports/detector_lift_fire37_20260605/post_priorities_solidity.md
- reference/patterns.dsl/state-change-between-check-and-use-token-delta-boundary.yaml
- reference/patterns.dsl/erc4337-paymaster-no-sender-validation.yaml
- reference/patterns.dsl/fx-v4core-swap-fee-equality-check.yaml
- detectors/wave17/reentrancy_share_callback_midstate_fire37.py

Provenance and evidence limits:
- context_pack_id: auditooor.vault_context_pack.v1:resume:d13bd9d230bee9a9
- context_pack_hash: d13bd9d230bee9a9be7b0163da353a019de15118dc6e4d3986c543a54d28abff
- memory_receipt: .auditooor/memory_context_receipt.json
- R37: this detector emits source-state candidate evidence only.
- R40: fixtures are detector smoke tests, not exploit PoCs.
- R76: candidate promotion must grep-verify cited excerpts exist.
- R80: detector hits are not load-bearing exploit evidence.

Submission posture: NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "state-check-external-use-fire38"
DETECTOR_SEVERITY_DEFAULT = "Medium"
PROMOTION_ALLOWED = False
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"


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
    body_line: int


@dataclass(frozen=True)
class CheckedValue:
    identity: str
    kind: str
    check_start: int


@dataclass(frozen=True)
class Boundary:
    match: re.Match[str]
    label: str


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_OR_EXTERNAL_RE = re.compile(r"\b(?:public|external)\b", re.IGNORECASE)
_VIEW_OR_PURE_RE = re.compile(r"\b(?:view|pure)\b", re.IGNORECASE)
_SURFACE_RE = re.compile(
    r"(?is)\b(?:"
    r"validatePaymasterUserOp|PackedUserOperation|paymaster|EntryPoint|"
    r"sponsor|sponsored|userOp\s*\.\s*sender|sender|allowedSenders|"
    r"swap|exactInput|exactOutput|amountSpecified|hook|beforeSwap|afterSwap|"
    r"fee|swapFee|lpFee|protocolFee|MAX_SWAP_FEE|MAX_LP_FEE|"
    r"balanceOf|allowance|reserve|invariant|constantProduct|kInvariant|"
    r"settle|finali[sz]e|accept|charge|debit|consume"
    r")\b"
)
_ENTRY_CONTEXT_RE = re.compile(
    r"(?is)\b(?:"
    r"(?:validate|paymaster|sponsor|postOp|swap|hook|fee|collect|settle|"
    r"charge|debit|consume|balance|reserve|invariant|accept|execute|route)"
    r"[A-Za-z0-9_]*"
    r")\b"
)
_CHECK_RE = re.compile(r"(?is)\b(?:require|assert|if)\s*\((?P<expr>[^;{}]*)\)")
_IDENTITY_RE = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\s*(?:\[[^\];{}]+\]|\.\s*[A-Za-z_][A-Za-z0-9_]*))*"
)
_DOTTED_RE = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\b"
)
_BRACKET_KEY_RE = re.compile(r"\[\s*(?P<key>[^\]\n;]{1,140})\s*\]")
_CONSTANT_RE = re.compile(
    r"^(?:MAX|MIN|DEFAULT|ZERO|ONE|SIG|VALIDATION|FEE_DENOMINATOR|PIPS)[A-Z0-9_]*$"
)
_STOPWORDS = {
    "address",
    "assert",
    "bool",
    "bytes",
    "bytes32",
    "calldata",
    "else",
    "external",
    "false",
    "function",
    "if",
    "internal",
    "memory",
    "msg",
    "public",
    "pure",
    "require",
    "return",
    "returns",
    "storage",
    "string",
    "this",
    "true",
    "uint",
    "uint8",
    "uint16",
    "uint24",
    "uint32",
    "uint64",
    "uint112",
    "uint128",
    "uint160",
    "uint256",
    "view",
}
_KIND_RE = {
    "sender policy": re.compile(
        r"(?i)(?:userOp\s*\.\s*sender|sender|owner|account|wallet|user|payer|"
        r"sponsor|allow|allowed|whitelist|approved|authorized|eligible|policy)"
    ),
    "fee/config": re.compile(r"(?i)(?:fee|swapFee|lpFee|protocolFee|config|hook)"),
    "balance/reserve": re.compile(
        r"(?i)(?:balance|allowance|reserve|asset|credit|collateral|amountIn|delta)"
    ),
    "invariant": re.compile(r"(?i)(?:invariant|constantProduct|kBefore|kInvariant|^k$)"),
}
_EXTERNAL_BOUNDARY_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\bI[A-Za-z0-9_]*(?:Hook|Hooks|Policy|Paymaster|Receiver|Callback|"
    r"Manager|Router|Adapter|Swap|Fee|Oracle|Token)[A-Za-z0-9_]*"
    r"\s*\([^;{}]*\)\s*\.\s*"
    r"(?:before|after|on|validate|sponsor|quote|swap|settle|execute|"
    r"callback|notify|transfer|hook)[A-Za-z0-9_]*\s*\(|"
    r"\b[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\s*(?:\[[^\]]+\]|\.\s*[A-Za-z_][A-Za-z0-9_]*))*"
    r"\s*\.\s*"
    r"(?:before|after|on|validate|sponsor|quote|swap|settle|execute|"
    r"callback|notify|transfer|safeTransfer|transferFrom|call|delegatecall)"
    r"[A-Za-z0-9_]*\s*(?:\{|\()|"
    r"\b(?:safeTransferFrom|transferFrom|safeTransfer|transfer|sendValue)"
    r"\s*\("
    r")"
)
_MUTATION_BOUNDARY_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\]|\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)+"
    r"\s*(?:=|\+=|-=|\+\+|--)|"
    r"\b_?(?:set|update|sync|refresh|accrue|checkpoint|mutate|consume|"
    r"charge|debit|credit|settle|finali[sz]e|accept|record|mark)"
    r"[A-Za-z0-9_]*(?:Fee|Config|Balance|Reserve|Invariant|Policy|Sender|Sponsor|"
    r"Swap|Hook|State|Usage|Gas|Charge)?\s*\("
    r")"
)
_FRESH_RE = re.compile(
    r"(?i)(?:after|post|fresh|latest|current|updated|recomputed|reloaded|"
    r"revalidated|refreshed|actual|delta|received)"
)
_REVALIDATION_SOURCE_RE = re.compile(
    r"(?is)(?:"
    r"balanceOf\s*\(|allowance\s*\(|getReserves\s*\(|"
    r"\.\s*(?:swapFee|lpFee|protocolFee|fee|config|hook|balance|reserve)|"
    r"\b(?:poolConfig|feeConfig|configOf|allowedSenders|approvedSenders|"
    r"sponsored|policy|invariant|constantProduct|kInvariant)\b"
    r")"
)
_SUCCESS_ACCEPT_RE = re.compile(
    r"(?is)\b(?:SIG_VALIDATION_SUCCESS|validationData|return\s*\([^;]*(?:0|bytes32\s*\(\s*0\s*\)))"
)
_FINAL_ACCEPT_RE = re.compile(
    r"(?is)\b(?:"
    r"return|require|assert|if|"
    r"_?settle[A-Za-z0-9_]*|_?finali[sz]e[A-Za-z0-9_]*|"
    r"_?accept[A-Za-z0-9_]*|_?charge[A-Za-z0-9_]*|_?debit[A-Za-z0-9_]*|"
    r"_?consume[A-Za-z0-9_]*|_?sponsor[A-Za-z0-9_]*|_?spend[A-Za-z0-9_]*|"
    r"_?record[A-Za-z0-9_]*|_?validate[A-Za-z0-9_]*|"
    r"_?swap[A-Za-z0-9_]*|_?mint[A-Za-z0-9_]*|_?burn[A-Za-z0-9_]*|"
    r"transfer|safeTransfer|safeTransferFrom"
    r")"
)
_LOCAL_DECL_PREFIX_RE = re.compile(
    r"(?is)\b(?:uint(?:8|16|24|32|64|112|128|160|256)?|"
    r"int(?:8|16|24|32|64|128|256)?|bool|address|bytes32|bytes|"
    r"string|var|[A-Z][A-Za-z0-9_]*)\s+(?:memory|storage|calldata\s+)?$"
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
    pos = open_pos + 1
    while pos < len(source) and depth > 0:
        char = source[pos]
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
        pos += 1
    return pos - 1 if depth == 0 else -1


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    close_brace = _find_matching_delimiter(source, open_brace, "{", "}")
    if close_brace < 0:
        return None, open_brace
    return source[open_brace + 1:close_brace], close_brace + 1


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
        cursor = close_paren + 1
        while cursor < len(source):
            if source[cursor] == ";":
                break
            if source[cursor] == "{":
                body_start = cursor
                break
            cursor += 1
        if body_start < 0:
            pos = max(cursor, close_paren + 1)
            continue

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _line_for_offset(fn: FunctionSlice, offset: int) -> int:
    return fn.body_line + fn.body.count("\n", 0, max(0, offset))


def _normalise_identity(identity: str) -> str:
    return re.sub(r"\s+", "", identity or "")


def _identity_regex(identity: str) -> re.Pattern[str]:
    norm = _normalise_identity(identity)
    if "." in norm:
        return re.compile(r"\s*\.\s*".join(re.escape(part) for part in norm.split(".")))
    return re.compile(rf"(?<!\.)\b{re.escape(norm)}\b")


def _classify_identity(identity: str, expr: str) -> str | None:
    norm = _normalise_identity(identity)
    if not norm:
        return None
    if norm in _STOPWORDS or _CONSTANT_RE.fullmatch(norm):
        return None
    if _FRESH_RE.search(norm):
        return None
    if _KIND_RE["invariant"].search(norm):
        return "invariant"
    for kind in ("sender policy", "fee/config", "balance/reserve"):
        if _KIND_RE[kind].search(norm):
            return kind
    return None


def _add_checked(out: list[CheckedValue], seen: set[str], identity: str, expr: str, start: int) -> None:
    identity = _normalise_identity(identity)
    kind = _classify_identity(identity, expr)
    if kind is None or identity in seen:
        return
    seen.add(identity)
    out.append(CheckedValue(identity=identity, kind=kind, check_start=start))


def _checked_values_from_expr(expr: str, start: int) -> list[CheckedValue]:
    out: list[CheckedValue] = []
    seen: set[str] = set()
    dotted_parts: set[str] = set()

    for match in _DOTTED_RE.finditer(expr):
        dotted = match.group(0)
        _add_checked(out, seen, dotted, expr, start)
        dotted_parts.update(part.strip() for part in dotted.split("."))

    for match in _BRACKET_KEY_RE.finditer(expr):
        key = match.group("key")
        _add_checked(out, seen, key, expr, start)
        if "." in key:
            dotted_parts.update(part.strip() for part in key.split("."))

    for match in _IDENTITY_RE.finditer(expr):
        identity = _normalise_identity(match.group(0))
        if "[" in identity:
            base = identity.split("[", 1)[0]
            _add_checked(out, seen, base, expr, start)
            continue
        if "." in identity:
            _add_checked(out, seen, identity, expr, start)
            continue
        if identity in dotted_parts:
            continue
        _add_checked(out, seen, identity, expr, start)
    return out


def _checked_values_before(body: str, boundary_start: int) -> list[CheckedValue]:
    prefix = body[:boundary_start]
    checked: list[CheckedValue] = []
    seen: set[str] = set()
    for match in _CHECK_RE.finditer(prefix):
        for value in _checked_values_from_expr(match.group("expr"), match.start()):
            if value.identity in seen:
                continue
            seen.add(value.identity)
            checked.append(value)
    return checked


def _statement_ranges(source: str, start: int) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    stmt_start = start
    depth = 0
    for pos in range(start, len(source)):
        char = source[pos]
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth > 0:
            depth -= 1
        elif char == ";" and depth == 0:
            ranges.append((stmt_start, pos + 1, source[stmt_start:pos + 1]))
            stmt_start = pos + 1
    tail = source[stmt_start:].strip()
    if tail:
        ranges.append((stmt_start, len(source), source[stmt_start:]))
    return ranges


def _is_local_assignment_statement(statement: str, identity: str) -> bool:
    ident_re = re.escape(_normalise_identity(identity))
    match = re.search(rf"(?is)\b{ident_re}\b\s*(?:=|\+=|-=|\*=|/=)", statement)
    if match is None:
        return False
    line_start = statement.rfind("\n", 0, match.start()) + 1
    prefix = statement[line_start:match.start()]
    return bool(_LOCAL_DECL_PREFIX_RE.search(prefix))


def _is_reload_or_revalidation(statement: str, checked: CheckedValue) -> bool:
    identity_re = _identity_regex(checked.identity)
    if re.search(r"(?is)\b(?:require|assert|if)\s*\(", statement):
        if identity_re.search(statement):
            return True
        if _FRESH_RE.search(statement) and _REVALIDATION_SOURCE_RE.search(statement):
            return True
    if re.search(
        rf"(?is)\b{re.escape(_normalise_identity(checked.identity))}\b\s*=\s*"
        rf"[^;]*(?:balanceOf\s*\(|allowance\s*\(|getReserves\s*\(|"
        rf"poolConfig|feeConfig|allowedSenders|approvedSenders|sponsored|"
        rf"invariant|constantProduct|kInvariant|reserve|balance|fee|config)",
        statement,
    ):
        return True
    if _FRESH_RE.search(statement) and _REVALIDATION_SOURCE_RE.search(statement):
        return True
    return False


def _has_revalidation(segment: str, checked: CheckedValue) -> bool:
    for _start, _end, statement in _statement_ranges(segment, 0):
        if _is_reload_or_revalidation(statement, checked):
            return True
    return False


def _stale_acceptance_use(statement: str, checked: CheckedValue, fn: FunctionSlice) -> bool:
    identity_re = _identity_regex(checked.identity)
    if _is_reload_or_revalidation(statement, checked):
        return False

    if identity_re.search(statement):
        if _is_local_assignment_statement(statement, checked.identity):
            return False
        return bool(_FINAL_ACCEPT_RE.search(statement) or re.search(r"(?:=|\+=|-=)", statement))

    if checked.kind == "sender policy":
        fn_context = f"{fn.name}\n{fn.header}\n{fn.body}"
        if re.search(r"(?is)(?:validatePaymasterUserOp|paymaster|UserOperation|sponsor)", fn_context):
            return bool(_SUCCESS_ACCEPT_RE.search(statement))
    return False


def _boundary_candidates(body: str, start: int) -> list[Boundary]:
    candidates: list[Boundary] = []
    for match in _EXTERNAL_BOUNDARY_RE.finditer(body, start):
        candidates.append(Boundary(match=match, label="external call"))
    for match in _MUTATION_BOUNDARY_RE.finditer(body, start):
        statement_start = max(body.rfind(";", 0, match.start()), body.rfind("\n", 0, match.start())) + 1
        prefix = body[statement_start:match.start()]
        if _LOCAL_DECL_PREFIX_RE.search(prefix):
            continue
        candidates.append(Boundary(match=match, label="mutable state transition"))
    return sorted(candidates, key=lambda item: item.match.start())


def _first_stale_use_after_boundary(
    fn: FunctionSlice,
    boundary: Boundary,
    checked: CheckedValue,
) -> tuple[int, str] | None:
    body = fn.body
    segment_start = boundary.match.end()
    for stmt_start, _stmt_end, statement in _statement_ranges(body, segment_start):
        between = body[segment_start:stmt_start]
        if _has_revalidation(between, checked):
            return None
        if _is_reload_or_revalidation(statement, checked):
            return None
        if _stale_acceptance_use(statement, checked, fn):
            return stmt_start, statement.strip()
    return None


def _candidate_function(fn: FunctionSlice) -> bool:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return False
    if _VIEW_OR_PURE_RE.search(fn.header):
        return False
    surface = f"{fn.name}\n{fn.header}\n{fn.body}"
    return bool(_ENTRY_CONTEXT_RE.search(surface) and _SURFACE_RE.search(surface))


def _match_function(fn: FunctionSlice) -> tuple[CheckedValue, Boundary, int] | None:
    if not _candidate_function(fn):
        return None

    for boundary in _boundary_candidates(fn.body, 0):
        checked_values = _checked_values_before(fn.body, boundary.match.start())
        if not checked_values:
            continue
        for checked in checked_values:
            if checked.kind == "sender policy" and boundary.label != "external call":
                continue
            stale_use = _first_stale_use_after_boundary(fn, boundary, checked)
            if stale_use is None:
                continue
            use_offset, _statement = stale_use
            return checked, boundary, use_offset
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    findings: list[Finding] = []
    if not source or _SURFACE_RE.search(source) is None:
        return findings

    clean_source = _strip_comments_and_strings(source)
    if _SURFACE_RE.search(clean_source) is None:
        return findings

    for fn in _split_functions(clean_source):
        matched = _match_function(fn)
        if matched is None:
            continue
        checked, boundary, use_offset = matched
        boundary_line = _line_for_offset(fn, boundary.match.start())
        use_line = _line_for_offset(fn, use_offset)
        article = "an" if boundary.label.startswith("external") else "a"
        boundary_text = re.sub(r"\s+", " ", boundary.match.group(0)).strip()
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=use_line,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` checks {checked.kind} `{checked.identity}` before "
                    f"{article} {boundary.label} near line {boundary_line}, then uses that "
                    f"stale checked value for final acceptance near line {use_line}. "
                    f"Boundary: `{boundary_text[:100]}`. Reload or revalidate the "
                    "sender, fee, balance, reserve, or invariant after the boundary. "
                    "NOT_SUBMIT_READY detector_fixture_smoke_only."
                ),
            )
        )
    return findings


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "PROMOTION_ALLOWED",
    "SUBMISSION_POSTURE",
    "scan",
]
