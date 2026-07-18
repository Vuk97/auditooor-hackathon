"""
missing-recipient-param-order-fire30

Regex API detector for settlement and transfer paths that already have a
recipient, receiver, taker, or toReceiver binding, but pass a maker, sender,
caller, or alias of those values as the recipient argument to transferFrom,
safeTransferFrom, _transfer, safeTransfer, or a native payout.

Source refs:
* reports/detector_lift_fire29_20260605/post_priorities_all.md
* reference/patterns.dsl/withdraw-claim-recipient-ignored-hardcoded-sink.yaml
* reference/patterns.dsl/dh-odos-exchange-unset-toReceiver.yaml
* reference/patterns.dsl/glider-accounting-updates-not-assuming-fee-on-transfers.yaml

Detector hits are candidate evidence only. They are NOT_SUBMIT_READY and must
not be used as exploit proof without R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "missing-recipient-param-order-fire30"
DETECTOR_SEVERITY_DEFAULT = "Medium"
PROMOTION_ALLOWED = False
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
SOURCE_REFS = (
    "reports/detector_lift_fire29_20260605/post_priorities_all.md",
    "reference/patterns.dsl/withdraw-claim-recipient-ignored-hardcoded-sink.yaml",
    "reference/patterns.dsl/dh-odos-exchange-unset-toReceiver.yaml",
    "reference/patterns.dsl/glider-accounting-updates-not-assuming-fee-on-transfers.yaml",
)


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


@dataclass
class FunctionSlice:
    name: str
    header: str
    body: str
    function_line: int
    body_line: int


@dataclass
class TransferSink:
    reason: str
    sink: str
    call_name: str
    args: list[str]
    anchor: re.Match[str]


_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b", re.IGNORECASE)
_SKIP_RE = re.compile(r"\b(?:mock|test|fixture|harness|example|demo)\b", re.IGNORECASE)

_CONTEXT_RE = re.compile(
    r"\b(order|orders|match|matched|fill|filled|settle|settlement|claim|"
    r"payout|refund|redeem|withdraw|transfer|trade|swap|exchange|route|"
    r"router|escrow|proceeds|amountOut|maker|taker|sender|receiver|recipient|toReceiver)\b",
    re.IGNORECASE,
)
_VALUE_CONTEXT_RE = re.compile(
    r"\b(safeTransferFrom|transferFrom|_transfer|safeTransfer|transfer|"
    r"sendValue|call\s*\{|amountOut|proceeds|payout|settle|fill)\b",
    re.IGNORECASE,
)

_ADDRESS_PARAM_RE = re.compile(
    r"\baddress(?:\s+payable)?\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_DEST_NAME_RE = re.compile(
    r"^(?:_?to|recipient|receiver|beneficiary|payee|payoutTo|payoutSink|"
    r"refundTo|refundRecipient|settlementRecipient|claimRecipient|"
    r"tradeRecipient|fillRecipient|toReceiver|dstReceiver|destination|"
    r"recipientAddress|receiverAddress|taker|buyer|matchedTaker)$",
    re.IGNORECASE,
)
_DEST_FIELD_RE = re.compile(
    r"\b(?P<root>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<field>_?to|recipient|receiver|beneficiary|payee|payoutTo|"
    r"refundTo|refundRecipient|settlementRecipient|claimRecipient|"
    r"tradeRecipient|fillRecipient|toReceiver|dstReceiver|destination|"
    r"recipientAddress|receiverAddress|taker|buyer|matchedTaker)\b",
    re.IGNORECASE,
)
_RECIPIENT_WORD_RE = re.compile(
    r"(recipient|receiver|beneficiary|payee|payout|refund|toReceiver|"
    r"dstReceiver|destination|taker|buyer)",
    re.IGNORECASE,
)
_UNSAFE_DIRECT_RE = re.compile(
    r"^(?:"
    r"msg\.sender|_msgSender\(\)|tx\.origin|owner\(\)|owner|sender|from|"
    r"maker|seller|operator|relayer|executor|caller|payer|account|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?\.(?:maker|sender|from|seller|owner|operator|relayer|executor|caller|payer|account)"
    r")$",
    re.IGNORECASE,
)
_CALL_RE = re.compile(
    r"\b(?P<name>safeTransferFrom|transferFrom|_transfer|safeTransfer|"
    r"transfer|sendValue|_mint|mint)\s*\(",
    re.IGNORECASE,
)
_NATIVE_PAYABLE_RE = re.compile(
    r"\bpayable\s*\(\s*(?P<sink>[^(){};]+?)\s*\)\s*\.\s*(?:call|transfer|send)\b",
    re.IGNORECASE | re.DOTALL,
)
_NATIVE_CALL_RE = re.compile(
    r"\b(?P<sink>[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?|"
    r"msg\.sender|_msgSender\s*\(\s*\))\s*\.\s*call\s*\{\s*value\s*:",
    re.IGNORECASE | re.DOTALL,
)
_ASSIGNMENT_RE = re.compile(
    r"(?is)\b(?:address(?:\s+payable)?\s+)?"
    r"(?P<left>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<right>[^;]+);"
)
_CONDITION_RE = re.compile(r"\b(?:require|assert|if)\s*\((?P<expr>[^;{}]*)\)", re.DOTALL)
_VALIDATOR_RE = re.compile(
    r"\b(?:validate|check|assert|bind|verify|hash)[A-Za-z0-9_]*"
    r"(?:Recipient|Receiver|Beneficiary|Payout|Sink|Settlement|Taker|Route|Order)"
    r"[A-Za-z0-9_]*\s*\((?P<args>[^;{}]*)\)",
    re.IGNORECASE | re.DOTALL,
)
_REVERT_WORD_RE = re.compile(
    r"(revert|RecipientMismatch|InvalidRecipient|InvalidReceiver|BadRecipient|"
    r"BadReceiver|NotRecipient|Unauthorized|InvalidTaker)",
    re.IGNORECASE,
)
_REFUNDISH_RE = re.compile(r"(refund|change|dust|leftover|surplus|fee|gas)", re.IGNORECASE)


def _strip_comments(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_RE.sub(replace, source or "")


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    if open_brace < 0 or open_brace >= len(source) or source[open_brace] != "{":
        return None, open_brace
    depth = 1
    i = open_brace + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
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

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        out.append(
            FunctionSlice(
                name=name,
                header=header,
                body=body,
                function_line=source.count("\n", 0, match.start()) + 1,
                body_line=source.count("\n", 0, body_start + 1) + 1,
            )
        )
        pos = end_pos
    return out


def _line_for(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _normalise_expr(expr: str) -> str:
    norm = re.sub(r"\s+", "", expr or "")
    while norm.startswith("payable(") and norm.endswith(")"):
        norm = norm[len("payable("):-1]
    return norm


def _expr_regex(expr: str) -> str:
    return r"\s*\.\s*".join(re.escape(part) for part in _normalise_expr(expr).split("."))


def _extract_call_args(body: str, open_paren: int) -> list[str]:
    if open_paren < 0 or open_paren >= len(body) or body[open_paren] != "(":
        return []
    args: list[str] = []
    current: list[str] = []
    depth_paren = 1
    depth_bracket = 0
    depth_brace = 0
    in_string: str | None = None
    escaped = False
    i = open_paren + 1
    while i < len(body) and depth_paren > 0:
        char = body[i]
        if in_string:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == in_string:
                in_string = None
            i += 1
            continue
        if char in ("'", '"'):
            in_string = char
            current.append(char)
        elif char == "(":
            depth_paren += 1
            current.append(char)
        elif char == ")":
            depth_paren -= 1
            if depth_paren > 0:
                current.append(char)
        elif char == "[":
            depth_bracket += 1
            current.append(char)
        elif char == "]":
            depth_bracket = max(0, depth_bracket - 1)
            current.append(char)
        elif char == "{":
            depth_brace += 1
            current.append(char)
        elif char == "}":
            depth_brace = max(0, depth_brace - 1)
            current.append(char)
        elif char == "," and depth_paren == 1 and depth_bracket == 0 and depth_brace == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        i += 1

    if depth_paren == 0:
        args.append("".join(current).strip())
    return args


def _recipient_sources(fn: FunctionSlice) -> list[str]:
    sources: list[str] = []
    for match in _ADDRESS_PARAM_RE.finditer(fn.header):
        name = match.group("name")
        if _DEST_NAME_RE.search(name):
            sources.append(_normalise_expr(name))

    for match in _DEST_FIELD_RE.finditer(fn.header + "\n" + fn.body):
        sources.append(_normalise_expr(f"{match.group('root')}.{match.group('field')}"))

    deduped: list[str] = []
    for source in sources:
        if source and source not in deduped:
            deduped.append(source)
    return deduped


def _is_unsafe_direct(expr: str) -> bool:
    norm = _normalise_expr(expr)
    if _RECIPIENT_WORD_RE.search(norm):
        return False
    return bool(_UNSAFE_DIRECT_RE.search(norm))


def _assignment_facts(body: str, sources: list[str]) -> tuple[set[str], set[str], set[str]]:
    source_aliases = set(sources)
    unsafe_aliases: set[str] = set()
    overwritten_sources: set[str] = set()

    changed = True
    while changed:
        changed = False
        for match in _ASSIGNMENT_RE.finditer(body):
            left = _normalise_expr(match.group("left"))
            right = _normalise_expr(match.group("right"))
            if not left or not right:
                continue
            if right in source_aliases and left not in source_aliases:
                source_aliases.add(left)
                changed = True
            if right in unsafe_aliases or _is_unsafe_direct(right):
                if left not in unsafe_aliases:
                    unsafe_aliases.add(left)
                    changed = True
                if left in source_aliases:
                    overwritten_sources.add(left)

    return source_aliases, unsafe_aliases, overwritten_sources


def _source_has_validation(body: str, source: str) -> bool:
    norm_source = _normalise_expr(source)
    for match in _CONDITION_RE.finditer(body):
        expr = _normalise_expr(match.group("expr"))
        if norm_source not in expr:
            continue
        if "address(0)" in expr or "==" in expr or "!=" in expr:
            if match.group(0).lower().startswith("if"):
                tail = body[match.end():match.end() + 200]
                if _REVERT_WORD_RE.search(expr + tail):
                    return True
            else:
                return True
    for match in _VALIDATOR_RE.finditer(body):
        if norm_source in _normalise_expr(match.group("args")):
            return True
    return False


def _has_any_validated_source(body: str, sources: list[str]) -> bool:
    return any(_source_has_validation(body, source) for source in sources)


def _condition_binds_source_to_sink(condition: str, source: str, sink: str) -> bool:
    expr = _normalise_expr(condition)
    source_norm = _normalise_expr(source)
    sink_norm = _normalise_expr(sink)
    if source_norm not in expr or sink_norm not in expr:
        return False
    without_zero = expr.replace("address(0)", "")
    return source_norm in without_zero and sink_norm in without_zero and (
        "==" in without_zero or "!=" in without_zero
    )


def _has_binding_guard(body: str, source: str, sink: str) -> bool:
    for match in _CONDITION_RE.finditer(body):
        expr = match.group("expr")
        if not _condition_binds_source_to_sink(expr, source, sink):
            continue
        if match.group(0).lower().startswith("if"):
            tail = body[match.end():match.end() + 200]
            if _REVERT_WORD_RE.search(expr + tail):
                return True
        else:
            return True
    for match in _VALIDATOR_RE.finditer(body):
        args = _normalise_expr(match.group("args"))
        if _normalise_expr(source) in args and _normalise_expr(sink) in args:
            return True
    return False


def _collect_transfer_sinks(body: str) -> list[TransferSink]:
    sinks: list[TransferSink] = []
    for match in _CALL_RE.finditer(body):
        call_name = match.group("name")
        args = _extract_call_args(body, match.end() - 1)
        if not args:
            continue

        lowered = call_name.lower()
        sink_index = 1 if lowered in {"safetransferfrom", "transferfrom", "_transfer"} else 0
        if len(args) <= sink_index:
            continue

        sink = _normalise_expr(args[sink_index])
        reason = f"passes `{sink}` as the recipient argument to `{call_name}`"
        sinks.append(
            TransferSink(reason=reason, sink=sink, call_name=call_name, args=args, anchor=match)
        )

    for match in _NATIVE_PAYABLE_RE.finditer(body):
        sink = _normalise_expr(match.group("sink"))
        sinks.append(
            TransferSink(
                reason=f"routes native payout to `{sink}`",
                sink=sink,
                call_name="native-payout",
                args=[sink],
                anchor=match,
            )
        )

    for match in _NATIVE_CALL_RE.finditer(body):
        sink = _normalise_expr(match.group("sink"))
        sinks.append(
            TransferSink(
                reason=f"routes native payout to `{sink}`",
                sink=sink,
                call_name="native-call",
                args=[sink],
                anchor=match,
            )
        )

    return sinks


def _is_refundish_sink(sink: TransferSink) -> bool:
    return sink.sink in {"msg.sender", "_msgSender()"} and any(
        _REFUNDISH_RE.search(arg or "") for arg in sink.args
    )


def _is_unsafe_sink(sink: str, unsafe_aliases: set[str]) -> bool:
    norm = _normalise_expr(sink)
    if norm in unsafe_aliases:
        return True
    return _is_unsafe_direct(norm)


def _match_function(fn: FunctionSlice) -> tuple[str, TransferSink] | None:
    if not _CALLABLE_HEADER_RE.search(fn.header):
        return None
    text = fn.header + "\n" + fn.body
    if not _CONTEXT_RE.search(fn.name) and not _CONTEXT_RE.search(text):
        return None
    if not _VALUE_CONTEXT_RE.search(fn.body):
        return None

    sources = _recipient_sources(fn)
    if not sources or not _has_any_validated_source(fn.body, sources):
        return None

    source_aliases, unsafe_aliases, overwritten_sources = _assignment_facts(fn.body, sources)
    for sink in _collect_transfer_sinks(fn.body):
        sink_norm = _normalise_expr(sink.sink)
        if _is_refundish_sink(sink):
            continue
        if sink_norm in overwritten_sources:
            return sources[0], sink
        if sink_norm in source_aliases:
            continue
        if not _is_unsafe_sink(sink_norm, unsafe_aliases):
            continue
        if any(_has_binding_guard(fn.body, source, sink_norm) for source in sources):
            continue
        return sources[0], sink

    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    if _SKIP_RE.search(file_path):
        return []

    clean_source = _strip_comments(source)
    findings: list[Finding] = []
    for fn in _split_functions(clean_source):
        matched = _match_function(fn)
        if matched is None:
            continue
        source, sink = matched
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn, sink.anchor),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` validates recipient evidence `{source}` but {sink.reason}. "
                    "Use the taker, receiver, or explicit recipient as the transfer recipient, "
                    "or assert the maker, sender, and recipient are the same before settlement. "
                    "NOT_SUBMIT_READY: detector fixture smoke only."
                ),
            )
        )
    return findings


__all__ = [
    "scan",
    "Finding",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "PROMOTION_ALLOWED",
    "SUBMISSION_POSTURE",
    "SOURCE_REFS",
]
