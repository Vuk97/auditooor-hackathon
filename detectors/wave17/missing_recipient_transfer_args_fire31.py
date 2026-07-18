"""
missing-recipient-transfer-args-fire31

Regex API detector for transfer and bridge functions that accept
caller-supplied token, amount, and recipient values, but either fail to reject
the zero recipient, validate a different address parameter, or hardcode the
outbound recipient to msg.sender, owner, or another non-recipient sink.

Source refs:
* reports/detector_lift_fire30_20260605/post_priorities_all.md
* reports/detector_lift_fire30_20260605/post_priorities_solidity.md
* detectors/wave17/missing_recipient_param_order_fire30.py
* tools/tests/test_missing_recipient_param_order_fire30.py

Detector hits are candidate evidence only. They are NOT_SUBMIT_READY and must
not be used as exploit proof without R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "missing-recipient-transfer-args-fire31"
DETECTOR_SEVERITY_DEFAULT = "Medium"
PROMOTION_ALLOWED = False
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
SOURCE_REFS = (
    "reports/detector_lift_fire30_20260605/post_priorities_all.md",
    "reports/detector_lift_fire30_20260605/post_priorities_solidity.md",
    "detectors/wave17/missing_recipient_param_order_fire30.py",
    "tools/tests/test_missing_recipient_param_order_fire30.py",
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
class ValueEdge:
    reason: str
    sink: str
    call_name: str
    args: list[str]
    anchor: re.Match[str]


_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public)\b", re.IGNORECASE)
_ADDRESS_PARAM_RE = re.compile(
    r"\baddress(?:\s+payable)?\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_UINT_PARAM_RE = re.compile(
    r"\buint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_FIELD_REF_RE = re.compile(
    r"\b(?P<root>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_TOKEN_NAME_RE = re.compile(
    r"^(?:_?token|asset|currency|coin|erc20|paymentToken|collateral|"
    r"inputToken|outputToken|srcToken|dstToken|bridgeToken|rewardToken|"
    r"depositToken|withdrawToken|underlying)$",
    re.IGNORECASE,
)
_AMOUNT_NAME_RE = re.compile(
    r"^(?:_?amount|amountIn|amountOut|assets|shares|quantity|qty|value|"
    r"size|paymentAmount|bridgeAmount|claimAmount|withdrawAmount|depositAmount)$",
    re.IGNORECASE,
)
_RECIPIENT_NAME_RE = re.compile(
    r"^(?:_?to|recipient|receiver|beneficiary|payee|payoutTo|payoutSink|"
    r"refundTo|refundRecipient|settlementRecipient|claimRecipient|"
    r"tradeRecipient|fillRecipient|toReceiver|dstReceiver|destination|"
    r"recipientAddress|receiverAddress|remoteRecipient|targetRecipient)$",
    re.IGNORECASE,
)
_FLOW_CONTEXT_RE = re.compile(
    r"(transfer|send|bridge|deposit|withdraw|claim|redeem|release|exit|"
    r"payout|payOut|route|swap|dispatch|relay|message|crossChain|dst|"
    r"recipient|receiver|amount|asset|token)",
    re.IGNORECASE,
)
_VALUE_CONTEXT_RE = re.compile(
    r"\b(safeTransferFrom|transferFrom|_transfer|safeTransfer|transfer|"
    r"sendValue|call\s*\{|_mint|mint|bridge|dispatch|relay|send|emit)\b",
    re.IGNORECASE,
)
_TRANSFER_CALL_RE = re.compile(
    r"\b(?P<name>safeTransferFrom|transferFrom|_transfer|safeTransfer|"
    r"transfer|sendValue|_mint|mint)\s*\(",
    re.IGNORECASE,
)
_GENERAL_CALL_RE = re.compile(
    r"\b(?:emit\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.IGNORECASE,
)
_BRIDGE_CALL_NAME_RE = re.compile(
    r"(bridge|send|dispatch|relay|message|packet|cross|deposit|withdraw|"
    r"mint|queue|enqueue|outbound|remote|xfer|transfer)",
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
    r"\b(?:validate|check|assert|bind|verify)[A-Za-z0-9_]*"
    r"(?:Recipient|Receiver|Beneficiary|Payout|Sink|Destination|Route)"
    r"[A-Za-z0-9_]*\s*\((?P<args>[^;{}]*)\)",
    re.IGNORECASE | re.DOTALL,
)
_REVERT_WORD_RE = re.compile(
    r"(revert|RecipientMismatch|InvalidRecipient|InvalidReceiver|BadRecipient|"
    r"BadReceiver|NotRecipient|ZeroRecipient|Unauthorized)",
    re.IGNORECASE,
)
_HARDCODED_DIRECT_RE = re.compile(
    r"^(?:msg\.sender|_msgSender\(\)|tx\.origin|owner\(\)|owner|"
    r"address\(this\)|this|vault|router|escrow|treasury|protocol|"
    r"feeReceiver|feeCollector|account|payer|operator|executor|relayer|"
    r"maker|sender|from|request\.account|withdrawal\.account|claim\.owner|"
    r"position\.owner|order\.maker|order\.sender|route\.sender|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?\.(?:maker|sender|from|owner|account|payer|operator|executor|relayer))$",
    re.IGNORECASE,
)
_CALLER_RE = re.compile(r"^(?:msg\.sender|_msgSender\(\))$", re.IGNORECASE)
_THIS_RE = re.compile(r"^(?:address\(this\)|this)$", re.IGNORECASE)
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


def _dedupe(items: list[str]) -> list[str]:
    out: list[str] = []
    for item in items:
        norm = _normalise_expr(item)
        if norm and norm not in out:
            out.append(norm)
    return out


def _named_sources(fn: FunctionSlice, name_re: re.Pattern[str], uints: bool = False) -> list[str]:
    sources: list[str] = []
    param_re = _UINT_PARAM_RE if uints else _ADDRESS_PARAM_RE
    for match in param_re.finditer(fn.header):
        name = match.group("name")
        if name_re.search(name) or name_re.search(name.strip("_")):
            sources.append(name)

    for match in _FIELD_REF_RE.finditer(fn.header + "\n" + fn.body):
        field = match.group("field")
        if name_re.search(field) or name_re.search(field.strip("_")):
            sources.append(f"{match.group('root')}.{field}")

    return _dedupe(sources)


def _token_sources(fn: FunctionSlice) -> list[str]:
    return _named_sources(fn, _TOKEN_NAME_RE)


def _amount_sources(fn: FunctionSlice) -> list[str]:
    return _named_sources(fn, _AMOUNT_NAME_RE, uints=True)


def _recipient_sources(fn: FunctionSlice) -> list[str]:
    return _named_sources(fn, _RECIPIENT_NAME_RE)


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


def _expr_mentions_any(expr: str, sources: list[str]) -> bool:
    norm = _normalise_expr(expr)
    return any(source in norm for source in sources)


def _source_has_zero_guard(body: str, source: str) -> bool:
    norm_source = _normalise_expr(source)
    for match in _CONDITION_RE.finditer(body):
        expr = _normalise_expr(match.group("expr"))
        if norm_source not in expr or "address(0)" not in expr:
            continue
        if match.group(0).lower().startswith("if"):
            tail = body[match.end():match.end() + 220]
            if _REVERT_WORD_RE.search(expr + tail):
                return True
        else:
            return True
    for match in _VALIDATOR_RE.finditer(body):
        if norm_source in _normalise_expr(match.group("args")):
            return True
    return False


def _recipient_has_zero_guard(body: str, sources: list[str]) -> bool:
    return any(_source_has_zero_guard(body, source) for source in sources)


def _first_wrong_zero_guard(body: str, token_sources: list[str]) -> str | None:
    for source in token_sources:
        if _source_has_zero_guard(body, source):
            return source
    return None


def _condition_binds_source_to_sink(condition: str, source: str, sink: str) -> bool:
    expr = _normalise_expr(condition)
    norm_source = _normalise_expr(source)
    norm_sink = _normalise_expr(sink)
    if norm_source not in expr or norm_sink not in expr:
        return False
    without_zero = expr.replace("address(0)", "")
    return (
        norm_source in without_zero
        and norm_sink in without_zero
        and ("==" in without_zero or "!=" in without_zero)
    )


def _has_binding_guard(body: str, source: str, sink: str) -> bool:
    for match in _CONDITION_RE.finditer(body):
        expr = match.group("expr")
        if not _condition_binds_source_to_sink(expr, source, sink):
            continue
        if match.group(0).lower().startswith("if"):
            tail = body[match.end():match.end() + 220]
            if _REVERT_WORD_RE.search(expr + tail):
                return True
        else:
            return True
    for match in _VALIDATOR_RE.finditer(body):
        args = _normalise_expr(match.group("args"))
        if _normalise_expr(source) in args and _normalise_expr(sink) in args:
            return True
    return False


def _assignment_facts(body: str, sources: list[str]) -> tuple[set[str], set[str], set[str]]:
    source_aliases = set(sources)
    hardcoded_aliases: set[str] = set()
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
            if right in hardcoded_aliases or _is_hardcoded_direct(right):
                if left not in hardcoded_aliases:
                    hardcoded_aliases.add(left)
                    changed = True
                if left in source_aliases:
                    overwritten_sources.add(left)

    return source_aliases, hardcoded_aliases, overwritten_sources


def _is_hardcoded_direct(expr: str) -> bool:
    return bool(_HARDCODED_DIRECT_RE.search(_normalise_expr(expr)))


def _is_hardcoded_sink(expr: str, hardcoded_aliases: set[str]) -> bool:
    norm = _normalise_expr(expr)
    return norm in hardcoded_aliases or _is_hardcoded_direct(norm)


def _is_inbound_pull(edge: ValueEdge) -> bool:
    lowered = edge.call_name.lower()
    if lowered not in {"safetransferfrom", "transferfrom"} or len(edge.args) < 2:
        return False
    from_arg = _normalise_expr(edge.args[0])
    to_arg = _normalise_expr(edge.args[1])
    return bool(_CALLER_RE.search(from_arg) and _THIS_RE.search(to_arg))


def _is_refundish_edge(edge: ValueEdge) -> bool:
    return bool(_CALLER_RE.search(_normalise_expr(edge.sink))) and any(
        _REFUNDISH_RE.search(arg or "") for arg in edge.args
    )


def _collect_transfer_edges(body: str) -> list[ValueEdge]:
    edges: list[ValueEdge] = []
    for match in _TRANSFER_CALL_RE.finditer(body):
        call_name = match.group("name")
        args = _extract_call_args(body, match.end() - 1)
        if not args:
            continue

        lowered = call_name.lower()
        sink_index = 1 if lowered in {"safetransferfrom", "transferfrom", "_transfer"} else 0
        if len(args) <= sink_index:
            continue

        sink = _normalise_expr(args[sink_index])
        reason = f"passes `{sink}` as recipient argument to `{call_name}`"
        edges.append(ValueEdge(reason=reason, sink=sink, call_name=call_name, args=args, anchor=match))

    for match in _NATIVE_PAYABLE_RE.finditer(body):
        sink = _normalise_expr(match.group("sink"))
        edges.append(
            ValueEdge(
                reason=f"routes native value to `{sink}`",
                sink=sink,
                call_name="native-payout",
                args=[sink],
                anchor=match,
            )
        )

    for match in _NATIVE_CALL_RE.finditer(body):
        sink = _normalise_expr(match.group("sink"))
        edges.append(
            ValueEdge(
                reason=f"routes native value to `{sink}`",
                sink=sink,
                call_name="native-call",
                args=[sink],
                anchor=match,
            )
        )

    return edges


def _source_arg_positions(args: list[str], sources: list[str]) -> set[int]:
    positions: set[int] = set()
    for i, arg in enumerate(args):
        if _expr_mentions_any(arg, sources):
            positions.add(i)
    return positions


def _collect_bridge_edges(
    body: str,
    token_sources: list[str],
    amount_sources: list[str],
    recipient_sources: list[str],
) -> list[ValueEdge]:
    transfer_names = {
        "safetransferfrom",
        "transferfrom",
        "_transfer",
        "safetransfer",
        "transfer",
        "sendvalue",
        "_mint",
        "mint",
    }
    edges: list[ValueEdge] = []
    for match in _GENERAL_CALL_RE.finditer(body):
        call_name = match.group("name")
        lowered = call_name.lower()
        if lowered in transfer_names or lowered in {"require", "assert", "if", "revert", "payable"}:
            continue
        if not _BRIDGE_CALL_NAME_RE.search(call_name):
            continue
        args = _extract_call_args(body, match.end() - 1)
        if len(args) < 3:
            continue
        if not any(_expr_mentions_any(arg, token_sources) for arg in args):
            continue
        if not any(_expr_mentions_any(arg, amount_sources) for arg in args):
            continue

        token_positions = _source_arg_positions(args, token_sources)
        amount_positions = _source_arg_positions(args, amount_sources)
        for i, arg in enumerate(args):
            if i in token_positions or i in amount_positions:
                continue
            sink = _normalise_expr(arg)
            if sink in recipient_sources or _is_hardcoded_direct(sink) or _RECIPIENT_NAME_RE.search(sink):
                edges.append(
                    ValueEdge(
                        reason=f"passes `{sink}` as bridge recipient argument to `{call_name}`",
                        sink=sink,
                        call_name=call_name,
                        args=args,
                        anchor=match,
                    )
                )
                break
    return edges


def _has_token_amount_flow(
    body: str,
    token_sources: list[str],
    amount_sources: list[str],
    edges: list[ValueEdge],
) -> bool:
    if not edges:
        return False
    text = _normalise_expr(body)
    return any(token in text for token in token_sources) and any(
        amount in text for amount in amount_sources
    )


def _match_function(fn: FunctionSlice) -> tuple[str, str, str, ValueEdge] | None:
    if not _CALLABLE_HEADER_RE.search(fn.header):
        return None
    if not _FLOW_CONTEXT_RE.search(fn.name) and not _FLOW_CONTEXT_RE.search(fn.header + fn.body):
        return None
    if not _VALUE_CONTEXT_RE.search(fn.body):
        return None

    token_sources = _token_sources(fn)
    amount_sources = _amount_sources(fn)
    recipient_sources = _recipient_sources(fn)
    if not token_sources or not amount_sources or not recipient_sources:
        return None

    transfer_edges = _collect_transfer_edges(fn.body)
    bridge_edges = _collect_bridge_edges(fn.body, token_sources, amount_sources, recipient_sources)
    edges = [edge for edge in transfer_edges + bridge_edges if not _is_inbound_pull(edge)]
    if not _has_token_amount_flow(fn.body, token_sources, amount_sources, edges):
        return None

    source_aliases, hardcoded_aliases, overwritten_sources = _assignment_facts(
        fn.body,
        recipient_sources,
    )

    for edge in edges:
        sink_norm = _normalise_expr(edge.sink)
        if _is_refundish_edge(edge):
            continue
        if sink_norm in source_aliases and sink_norm not in overwritten_sources:
            continue
        if any(_has_binding_guard(fn.body, source, sink_norm) for source in recipient_sources):
            continue
        if sink_norm in overwritten_sources or _is_hardcoded_sink(sink_norm, hardcoded_aliases):
            return (
                recipient_sources[0],
                sink_norm,
                f"hardcodes outbound recipient: {edge.reason}",
                edge,
            )

    if not _recipient_has_zero_guard(fn.body, recipient_sources):
        wrong_guard = _first_wrong_zero_guard(fn.body, token_sources)
        edge = edges[0]
        if wrong_guard:
            reason = (
                f"validates `{wrong_guard}` against address(0) but never rejects "
                f"zero recipient `{recipient_sources[0]}`"
            )
        else:
            reason = f"does not reject zero recipient `{recipient_sources[0]}`"
        return recipient_sources[0], _normalise_expr(edge.sink), reason, edge

    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean_source = _strip_comments(source)
    findings: list[Finding] = []
    for fn in _split_functions(clean_source):
        matched = _match_function(fn)
        if matched is None:
            continue
        recipient, sink, reason, edge = matched
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn, edge.anchor),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` accepts caller-supplied token, amount, and recipient "
                    f"`{recipient}`, but {reason} before value movement to `{sink}`. "
                    "Validate the recipient itself and route the transfer or bridge "
                    "payload to that recipient, or assert the hardcoded sink and "
                    "recipient are identical. NOT_SUBMIT_READY: detector fixture smoke only."
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
