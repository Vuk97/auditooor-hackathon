"""
recipient-payout-authority-fire33

Regex API detector for Solidity claim, payout, bridge receive, and credit paths
where a recipient-like endpoint is used as the value sink without proving that
it matches the authorized claimant, owner, account, or message recipient.

Source refs:
* reports/detector_lift_fire32_20260605/post_priorities_all.md
* reference/patterns.dsl/missing-recipient-validation-transfer-or-credit.yaml
* reference/patterns.dsl/missing-recipient-zero-address-destructive-sink.yaml
* reference/patterns.dsl/withdraw-claim-recipient-ignored-hardcoded-sink.yaml

Detector hits are candidate evidence only. They are NOT_SUBMIT_READY and must
not be used as exploit proof without R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "recipient-payout-authority-fire33"
DETECTOR_SEVERITY_DEFAULT = "Medium"
PROMOTION_ALLOWED = False
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"
SOURCE_REFS = (
    "reports/detector_lift_fire32_20260605/post_priorities_all.md",
    "reference/patterns.dsl/missing-recipient-validation-transfer-or-credit.yaml",
    "reference/patterns.dsl/missing-recipient-zero-address-destructive-sink.yaml",
    "reference/patterns.dsl/withdraw-claim-recipient-ignored-hardcoded-sink.yaml",
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
class StructShape:
    endpoints: list[str]
    authorities: list[str]
    amounts: list[str]
    tokens: list[str]


@dataclass
class ValueEdge:
    reason: str
    sink: str
    call_name: str
    args: list[str]
    anchor: re.Match[str]


_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_STRUCT_HEADER_RE = re.compile(r"\bstruct\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{")
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b", re.IGNORECASE)
_ADDRESS_PARAM_RE = re.compile(
    r"\baddress(?:\s+payable)?\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_UINT_PARAM_RE = re.compile(
    r"\buint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_STRUCT_PARAM_RE = re.compile(
    r"\b(?P<type>[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"(?:calldata|memory|storage)?\s*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_ADDRESS_FIELD_RE = re.compile(
    r"\baddress(?:\s+payable)?\s+(?P<field>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_UINT_FIELD_RE = re.compile(
    r"\buint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?\s+"
    r"(?P<field>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_FIELD_REF_RE = re.compile(
    r"\b(?P<root>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_ENDPOINT_NAME_RE = re.compile(
    r"^(?:_?to|recipient|receiver|beneficiary|payee|payoutTo|payoutSink|"
    r"refundTo|refundRecipient|settlementRecipient|claimRecipient|"
    r"tradeRecipient|fillRecipient|toReceiver|dstReceiver|destination|"
    r"remoteRecipient|targetRecipient|owner|account|claimant|user)$",
    re.IGNORECASE,
)
_AUTHORITY_NAME_RE = re.compile(
    r"^(?:owner|account|claimant|user|sender|from|maker|payer|operator|"
    r"executor|beneficiary|recipient|receiver|messageRecipient|expectedRecipient|"
    r"authorizedRecipient|authorizedClaimant|authorizedAccount)$",
    re.IGNORECASE,
)
_TOKEN_NAME_RE = re.compile(
    r"^(?:_?token|asset|currency|coin|erc20|paymentToken|collateral|"
    r"inputToken|outputToken|srcToken|dstToken|bridgeToken|rewardToken|"
    r"depositToken|withdrawToken|underlying)$",
    re.IGNORECASE,
)
_AMOUNT_NAME_RE = re.compile(
    r"^(?:_?amount|amountIn|amountOut|assets|shares|quantity|qty|value|"
    r"size|paymentAmount|bridgeAmount|claimAmount|withdrawAmount|depositAmount|"
    r"payoutAmount|creditAmount|proceeds|reward)$",
    re.IGNORECASE,
)
_FLOW_CONTEXT_RE = re.compile(
    r"(claim|withdraw|redeem|release|payout|payOut|bridge|receive|credit|"
    r"settle|settlement|refund|message|order|airdrop|merkle|proof|signature|"
    r"account|recipient|receiver|beneficiary|owner|amount|token|asset)",
    re.IGNORECASE,
)
_VALUE_CONTEXT_RE = re.compile(
    r"\b(safeTransferFrom|transferFrom|_transfer|safeTransfer|transfer|"
    r"sendValue|call\s*\{|_safeMint|_mint|mint|balances?\s*\[|credits?\s*\[|"
    r"claimable\s*\[|pending\s*\[|owed\s*\[|dispatch|bridge|send|route)\b",
    re.IGNORECASE,
)
_TRANSFER_CALL_RE = re.compile(
    r"\b(?P<name>safeTransferFrom|transferFrom|_transfer|safeTransfer|"
    r"transfer|sendValue|_safeMint|_mint|mint)\s*\(",
    re.IGNORECASE,
)
_GENERAL_CALL_RE = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.IGNORECASE,
)
_ROUTE_CALL_NAME_RE = re.compile(
    r"(bridge|receive|send|dispatch|relay|message|packet|cross|claim|"
    r"release|payout|payOut|route|settle|credit|remote|xfer|transfer)",
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
_CREDIT_WRITE_RE = re.compile(
    r"\b(?P<map>balances?|credits?|claimable|pending|owed|payouts?|rewards?|"
    r"escrowed|receivables?)\s*\[\s*(?P<sink>[^\]]+?)\s*\]\s*(?:\+=|=)",
    re.IGNORECASE | re.DOTALL,
)
_ASSIGNMENT_RE = re.compile(
    r"(?is)\b(?:address(?:\s+payable)?\s+)?"
    r"(?P<left>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<right>[^;]+);"
)
_CONDITION_RE = re.compile(r"\b(?:require|assert|if)\s*\((?P<expr>[^;{}]*)\)", re.DOTALL)
_VALIDATOR_RE = re.compile(
    r"\b(?:validate|check|assert|bind|verify|authorize|authenticate)"
    r"[A-Za-z0-9_]*(?:Recipient|Receiver|Beneficiary|Claim|Claimant|"
    r"Account|Owner|Message|Route|Payout|Authority)[A-Za-z0-9_]*"
    r"\s*\((?P<args>[^;{}]*)\)",
    re.IGNORECASE | re.DOTALL,
)
_REVERT_WORD_RE = re.compile(
    r"(revert|RecipientMismatch|InvalidRecipient|InvalidReceiver|BadRecipient|"
    r"BadReceiver|NotRecipient|Unauthorized|InvalidClaimant|InvalidAccount|"
    r"InvalidOwner|WrongRecipient|ClaimantMismatch)",
    re.IGNORECASE,
)
_ZERO_ADDRESS_RE = re.compile(r"address\s*\(\s*0\s*\)", re.IGNORECASE)
_CALLER_RE = re.compile(r"^(?:msg\.sender|_msgSender\(\))$", re.IGNORECASE)
_THIS_RE = re.compile(r"^(?:address\(this\)|this)$", re.IGNORECASE)
_REFUNDISH_RE = re.compile(r"(refund|change|dust|leftover|surplus|fee|gas)", re.IGNORECASE)
_PRIVILEGED_HEADER_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyOperator|requiresAuth|auth|"
    r"restricted|onlyGovernor|onlyGuardian)\b",
    re.IGNORECASE,
)


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


def _struct_shapes(source: str) -> dict[str, StructShape]:
    out: dict[str, StructShape] = {}
    pos = 0
    while True:
        match = _STRUCT_HEADER_RE.search(source, pos)
        if not match:
            break
        open_brace = source.find("{", match.end() - 1)
        body, end_pos = _extract_balanced_block(source, open_brace)
        if body is None:
            pos = match.end()
            continue

        endpoints: list[str] = []
        authorities: list[str] = []
        tokens: list[str] = []
        amounts: list[str] = []
        for field_match in _ADDRESS_FIELD_RE.finditer(body):
            field = field_match.group("field")
            if _ENDPOINT_NAME_RE.search(field):
                endpoints.append(field)
            if _AUTHORITY_NAME_RE.search(field):
                authorities.append(field)
            if _TOKEN_NAME_RE.search(field):
                tokens.append(field)
        for field_match in _UINT_FIELD_RE.finditer(body):
            field = field_match.group("field")
            if _AMOUNT_NAME_RE.search(field):
                amounts.append(field)
        out[match.group("name")] = StructShape(
            endpoints=_dedupe(endpoints),
            authorities=_dedupe(authorities),
            amounts=_dedupe(amounts),
            tokens=_dedupe(tokens),
        )
        pos = end_pos
    return out


def _struct_params(fn: FunctionSlice, shapes: dict[str, StructShape]) -> dict[str, str]:
    params: dict[str, str] = {}
    for match in _STRUCT_PARAM_RE.finditer(fn.header):
        type_name = match.group("type")
        if type_name in shapes:
            params[match.group("name")] = type_name
    return params


def _field_refs_by_name(
    fn: FunctionSlice,
    name_re: re.Pattern[str],
    shapes: dict[str, StructShape],
    shape_attr: str,
) -> list[str]:
    refs: list[str] = []
    text = fn.header + "\n" + fn.body
    for match in _FIELD_REF_RE.finditer(text):
        field = match.group("field")
        if name_re.search(field) or name_re.search(field.strip("_")):
            refs.append(f"{match.group('root')}.{field}")

    for param_name, type_name in _struct_params(fn, shapes).items():
        for field in getattr(shapes[type_name], shape_attr):
            refs.append(f"{param_name}.{field}")
    return _dedupe(refs)


def _address_params_by_name(fn: FunctionSlice, name_re: re.Pattern[str]) -> list[str]:
    refs: list[str] = []
    for match in _ADDRESS_PARAM_RE.finditer(fn.header):
        name = match.group("name")
        if name_re.search(name):
            refs.append(name)
    return _dedupe(refs)


def _uint_params_by_name(fn: FunctionSlice, name_re: re.Pattern[str]) -> list[str]:
    refs: list[str] = []
    for match in _UINT_PARAM_RE.finditer(fn.header):
        name = match.group("name")
        if name_re.search(name):
            refs.append(name)
    return _dedupe(refs)


def _endpoint_sources(fn: FunctionSlice, shapes: dict[str, StructShape]) -> list[str]:
    return _dedupe(
        _address_params_by_name(fn, _ENDPOINT_NAME_RE)
        + _field_refs_by_name(fn, _ENDPOINT_NAME_RE, shapes, "endpoints")
    )


def _authority_sources(fn: FunctionSlice, shapes: dict[str, StructShape]) -> list[str]:
    sources = (
        _address_params_by_name(fn, _AUTHORITY_NAME_RE)
        + _field_refs_by_name(fn, _AUTHORITY_NAME_RE, shapes, "authorities")
    )
    return _dedupe([source for source in sources if not _CALLER_RE.search(source)])


def _amount_sources(fn: FunctionSlice, shapes: dict[str, StructShape]) -> list[str]:
    return _dedupe(
        _uint_params_by_name(fn, _AMOUNT_NAME_RE)
        + _field_refs_by_name(fn, _AMOUNT_NAME_RE, shapes, "amounts")
    )


def _token_sources(fn: FunctionSlice, shapes: dict[str, StructShape]) -> list[str]:
    return _dedupe(
        _address_params_by_name(fn, _TOKEN_NAME_RE)
        + _field_refs_by_name(fn, _TOKEN_NAME_RE, shapes, "tokens")
    )


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
    return any(source and source in norm for source in sources)


def _assignment_aliases(body: str, sources: list[str]) -> set[str]:
    aliases = set(sources)
    changed = True
    while changed:
        changed = False
        for match in _ASSIGNMENT_RE.finditer(body):
            left = _normalise_expr(match.group("left"))
            right = _normalise_expr(match.group("right"))
            if right in aliases and left not in aliases:
                aliases.add(left)
                changed = True
    return aliases


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
        edges.append(
            ValueEdge(
                reason=f"moves value to `{sink}` through `{call_name}`",
                sink=sink,
                call_name=call_name,
                args=args,
                anchor=match,
            )
        )

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

    for match in _CREDIT_WRITE_RE.finditer(body):
        sink = _normalise_expr(match.group("sink"))
        edges.append(
            ValueEdge(
                reason=f"credits `{match.group('map')}[{sink}]`",
                sink=sink,
                call_name="credit-write",
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


def _collect_route_edges(
    body: str,
    token_sources: list[str],
    amount_sources: list[str],
    endpoint_aliases: set[str],
) -> list[ValueEdge]:
    transfer_names = {
        "safetransferfrom",
        "transferfrom",
        "_transfer",
        "safetransfer",
        "transfer",
        "sendvalue",
        "_safemint",
        "_mint",
        "mint",
        "payable",
        "require",
        "assert",
        "revert",
    }
    edges: list[ValueEdge] = []
    for match in _GENERAL_CALL_RE.finditer(body):
        call_name = match.group("name")
        lowered = call_name.lower()
        if lowered in transfer_names:
            continue
        if not _ROUTE_CALL_NAME_RE.search(call_name):
            continue
        args = _extract_call_args(body, match.end() - 1)
        if len(args) < 2:
            continue
        if token_sources and not any(_expr_mentions_any(arg, token_sources) for arg in args):
            continue
        if amount_sources and not any(_expr_mentions_any(arg, amount_sources) for arg in args):
            continue

        token_positions = _source_arg_positions(args, token_sources)
        amount_positions = _source_arg_positions(args, amount_sources)
        for i, arg in enumerate(args):
            if i in token_positions or i in amount_positions:
                continue
            sink = _normalise_expr(arg)
            if sink in endpoint_aliases:
                edges.append(
                    ValueEdge(
                        reason=f"forwards `{sink}` as route payout endpoint to `{call_name}`",
                        sink=sink,
                        call_name=call_name,
                        args=args,
                        anchor=match,
                    )
                )
                break
    return edges


def _condition_is_authority_guard(expr: str, endpoint: str, authorities: list[str]) -> bool:
    norm = _normalise_expr(expr)
    norm_endpoint = _normalise_expr(endpoint)
    if norm_endpoint not in norm:
        return False
    if _ZERO_ADDRESS_RE.search(expr) and not any(authority in norm for authority in authorities):
        return False
    has_counterparty = any(authority and authority in norm for authority in authorities)
    has_counterparty = has_counterparty or "msg.sender" in norm or "_msgSender()" in norm
    if not has_counterparty:
        return False
    return (
        "==" in norm
        or "!=" in norm
        or "allowed" in norm.lower()
        or "authorized" in norm.lower()
        or "whitelist" in norm.lower()
        or "canreceive" in norm.lower()
    )


def _has_authority_guard(body: str, endpoint: str, authorities: list[str]) -> bool:
    for match in _CONDITION_RE.finditer(body):
        expr = match.group("expr")
        if not _condition_is_authority_guard(expr, endpoint, authorities):
            continue
        if match.group(0).lower().startswith("if"):
            tail = body[match.end():match.end() + 240]
            if _REVERT_WORD_RE.search(expr + tail):
                return True
        else:
            return True

    norm_endpoint = _normalise_expr(endpoint)
    for match in _VALIDATOR_RE.finditer(body):
        args = _normalise_expr(match.group("args"))
        if norm_endpoint not in args:
            continue
        if any(authority and authority in args for authority in authorities):
            return True
        if "msg.sender" in args or "_msgSender()" in args:
            return True
    return False


def _has_non_endpoint_proof_or_guard(
    body: str,
    authority_sources: list[str],
    token_sources: list[str],
    amount_sources: list[str],
) -> bool:
    proof_words = re.compile(
        r"(proof|root|signature|signed|nonce|claimed|processed|message|"
        r"sourceChain|domain|order|claim|allowance|credit)",
        re.IGNORECASE,
    )
    if proof_words.search(body):
        return True
    for match in _CONDITION_RE.finditer(body):
        expr = _normalise_expr(match.group("expr"))
        if any(source and source in expr for source in authority_sources + token_sources + amount_sources):
            return True
    return False


def _match_function(
    fn: FunctionSlice,
    shapes: dict[str, StructShape],
) -> tuple[str, list[str], str, ValueEdge] | None:
    if not _CALLABLE_HEADER_RE.search(fn.header):
        return None
    if _PRIVILEGED_HEADER_RE.search(fn.header):
        return None
    if not _FLOW_CONTEXT_RE.search(fn.name) and not _FLOW_CONTEXT_RE.search(fn.header + fn.body):
        return None
    if not _VALUE_CONTEXT_RE.search(fn.body):
        return None

    endpoints = _endpoint_sources(fn, shapes)
    if not endpoints:
        return None
    endpoint_aliases = _assignment_aliases(fn.body, endpoints)
    authority_sources = _authority_sources(fn, shapes)
    token_sources = _token_sources(fn, shapes)
    amount_sources = _amount_sources(fn, shapes)
    if not amount_sources:
        return None

    edges = [
        edge
        for edge in _collect_transfer_edges(fn.body)
        if not _is_inbound_pull(edge) and not _is_refundish_edge(edge)
    ]
    edges.extend(_collect_route_edges(fn.body, token_sources, amount_sources, endpoint_aliases))
    if not edges:
        return None

    for edge in edges:
        sink = _normalise_expr(edge.sink)
        if sink not in endpoint_aliases:
            continue
        if not _has_non_endpoint_proof_or_guard(
            fn.body,
            authority_sources,
            token_sources,
            amount_sources,
        ):
            continue
        counterparty_sources = [source for source in authority_sources if source != sink]
        if _has_authority_guard(fn.body, sink, counterparty_sources):
            continue
        return sink, counterparty_sources, "recipient endpoint is not bound to claimant authority", edge

    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean_source = _strip_comments(source)
    shapes = _struct_shapes(clean_source)
    findings: list[Finding] = []
    for fn in _split_functions(clean_source):
        matched = _match_function(fn, shapes)
        if matched is None:
            continue
        endpoint, authorities, reason, edge = matched
        authority_text = ", ".join(f"`{authority}`" for authority in authorities[:4])
        if not authority_text:
            authority_text = "`msg.sender` or the verified message claimant"
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn, edge.anchor),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` moves value to recipient endpoint `{endpoint}` but {reason}; "
                    f"the function has claimant or message authority context {authority_text} "
                    f"and reaches `{edge.call_name}` without proving the endpoint matches it. "
                    "Bind the payout sink to the claimant, signed message recipient, or caller "
                    "before transfer, mint, credit, or route dispatch. NOT_SUBMIT_READY: "
                    "detector fixture smoke only."
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
    "VERIFICATION_TIER",
    "SOURCE_REFS",
]
