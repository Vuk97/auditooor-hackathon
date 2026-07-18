"""
missing-recipient-order-settlement-fire37

Regex API detector for Solidity order, claim, escrow, payout, and settlement
paths where a recipient-like sink comes from calldata or a hardcoded actor
instead of being bound to the signed order, claim proof, escrow owner, or
stored settlement target.

Source refs:
* reports/detector_lift_fire36_20260605/post_priorities_solidity.md
* reference/patterns.dsl/missing-recipient-validation-transfer-or-credit.yaml
* reference/patterns.dsl/missing-recipient-order-match-hardcoded-maker-sink.yaml
* detectors/wave17/missing_recipient_claim_sink_fire36.py
* detectors/wave17/recipient_settlement_target_fire35.py

Detector hits are candidate evidence only. They are NOT_SUBMIT_READY and must
not be used as exploit proof without R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "missing-recipient-order-settlement-fire37"
DETECTOR_SEVERITY_DEFAULT = "Medium"
PROMOTION_ALLOWED = False
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"
SOURCE_REFS = (
    "reports/detector_lift_fire36_20260605/post_priorities_solidity.md",
    "reference/patterns.dsl/missing-recipient-validation-transfer-or-credit.yaml",
    "reference/patterns.dsl/missing-recipient-order-match-hardcoded-maker-sink.yaml",
    "detectors/wave17/missing_recipient_claim_sink_fire36.py",
    "detectors/wave17/recipient_settlement_target_fire35.py",
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
    targets: list[str]
    authorities: list[str]
    commitment_fields: list[str]
    amounts: list[str]
    assets: list[str]


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
_STRUCT_PARAM_RE = re.compile(
    r"\b(?P<type>[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"(?:calldata|memory|storage)?\s*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_ADDRESS_PARAM_RE = re.compile(
    r"\baddress(?:\s+payable)?\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_UINT_PARAM_RE = re.compile(
    r"\buint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
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
_BYTES_FIELD_RE = re.compile(
    r"\b(?:bytes(?:[0-9]+)?|uint(?:[0-9]+)?|address)\s+"
    r"(?P<field>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_FIELD_REF_RE = re.compile(
    r"\b(?P<root>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_INDEXED_REF_RE = re.compile(
    r"\b(?P<root>[A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]]+\]\s*\.\s*"
    r"(?P<field>[A-Za-z_][A-Za-z0-9_]*)\b"
)

_SINK_PARAM_NAME_RE = re.compile(
    r"^(?:_?to|recipient|receiver|beneficiary|payee|payoutTo|payoutTarget|"
    r"settlementRecipient|settlementTarget|claimRecipient|fillRecipient|"
    r"tradeRecipient|refundTo|withdrawRecipient|releaseTo|account|owner|"
    r"maker|taker|claimant|claimer|seller|buyer)$",
    re.IGNORECASE,
)
_TARGET_FIELD_NAME_RE = re.compile(
    r"^(?:_?to|recipient|receiver|beneficiary|payee|payoutTo|payoutTarget|"
    r"settlementRecipient|settlementTarget|storedRecipient|storedTarget|"
    r"claimRecipient|canonicalRecipient|expectedRecipient|fillRecipient|"
    r"tradeRecipient|refundTo|withdrawRecipient|releaseTo|account|owner|"
    r"maker|taker|claimant|claimer|seller|buyer)$",
    re.IGNORECASE,
)
_AUTHORITY_NAME_RE = re.compile(
    r"^(?:owner|maker|taker|sender|from|account|user|claimant|claimer|payer|"
    r"operator|executor|relayer|seller|buyer|escrowOwner|orderOwner)$",
    re.IGNORECASE,
)
_ASSET_NAME_RE = re.compile(
    r"^(?:_?token|asset|currency|coin|erc20|paymentToken|collateral|"
    r"inputToken|outputToken|srcToken|dstToken|underlying)$",
    re.IGNORECASE,
)
_AMOUNT_NAME_RE = re.compile(
    r"^(?:_?amount|amountIn|amountOut|assets|shares|quantity|qty|value|"
    r"size|paymentAmount|claimAmount|settlementAmount|payoutAmount|"
    r"makerAmount|takerAmount|proceeds|price)$",
    re.IGNORECASE,
)
_COMMITMENT_FIELD_NAME_RE = re.compile(
    r"(proof|merkle|root|leaf|digest|hash|signature|sig|nonce|claimId|"
    r"orderId|settlementId|escrowId)",
    re.IGNORECASE,
)
_FLOW_CONTEXT_RE = re.compile(
    r"(order|orders|fill|match|trade|settle|settlement|claim|proof|escrow|"
    r"release|payout|payOut|withdraw|redeem|beneficiary|recipient|receiver|"
    r"maker|taker|owner|account|proceeds)",
    re.IGNORECASE,
)
_COMMITMENT_CONTEXT_RE = re.compile(
    r"(signature|signed|ecdsa|recover|verify|validate|hashOrder|hashClaim|"
    r"hashSettlement|hashEscrow|_hashTypedData|typedData|digest|proof|merkle|"
    r"leaf|root|escrow|settlement|claim)",
    re.IGNORECASE,
)
_VALUE_CONTEXT_RE = re.compile(
    r"\b(safeTransferFrom|transferFrom|_transfer|safeTransfer|transfer|"
    r"sendValue|call\s*\{|_safeMint|_mint|mint|balances?\s*\[|credits?\s*\[|"
    r"claimable\s*\[|pending\s*\[|owed\s*\[|payouts?\s*\[|proceeds\s*\[)\b",
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
    r"\b(?P<map>balances?|credits?|claimable|pending|owed|payouts?|proceeds|"
    r"receivables?)\s*\[\s*(?P<sink>[^\]]+?)\s*\]\s*(?:\+=|=)",
    re.IGNORECASE | re.DOTALL,
)
_ASSIGNMENT_RE = re.compile(
    r"(?is)\b(?:address(?:\s+payable)?\s+)?"
    r"(?P<left>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<right>[^;]+);"
)
_CONDITION_RE = re.compile(r"\b(?:require|assert|if)\s*\((?P<expr>[^;{}]*)\)", re.DOTALL)
_VALIDATOR_RE = re.compile(
    r"\b(?:validate|check|assert|bind|verify|authorize|authenticate)"
    r"[A-Za-z0-9_]*(?:Recipient|Receiver|Beneficiary|Target|Sink|Payout|"
    r"Settlement|Claim|Claimant|Account|Owner|Maker|Taker|Escrow|Order)"
    r"[A-Za-z0-9_]*\s*\((?P<args>[^;{}]*)\)",
    re.IGNORECASE | re.DOTALL,
)
_HASH_BINDING_CALL_RE = re.compile(
    r"\b(?:hash|hashOrder|hashClaim|hashSettlement|hashEscrow|_hashTypedData|"
    r"toTypedDataHash|hashTypedDataV4|keccak256|abi\.encode|abi\.encodePacked|"
    r"verify|validate|recover|tryRecover|isValidSignature|SignatureChecker)"
    r"[A-Za-z0-9_]*\s*\((?P<args>[^;{}]*)\)",
    re.IGNORECASE | re.DOTALL,
)
_REVERT_WORD_RE = re.compile(
    r"(revert|RecipientMismatch|TargetMismatch|InvalidRecipient|InvalidReceiver|"
    r"InvalidTarget|BadRecipient|BadReceiver|NotRecipient|Unauthorized|NotOwner|"
    r"WrongRecipient|ClaimantMismatch|MakerMismatch|TakerMismatch|OwnerMismatch|"
    r"AccountMismatch|SettlementTargetMismatch|EscrowOwnerMismatch|NotAllowed)",
    re.IGNORECASE,
)
_ALLOWLIST_WORD_RE = re.compile(
    r"(allowed|approved|authorized|whitelist|canReceive|recipientAllowlist)",
    re.IGNORECASE,
)
_HARDCODED_SINK_RE = re.compile(
    r"^(?:msg\.sender|_msgSender\(\)|tx\.origin|owner\(\)|owner|maker|taker|"
    r"operator|executor|relayer|payer|account|feeReceiver|feeCollector|"
    r"treasury|protocol|vault|router|escrow|settlementSink|payoutSink|"
    r"defaultSink|defaultRecipient|storedSink|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?\.(?:maker|taker|sender|from|"
    r"owner|account|operator|executor|relayer|payer|seller|buyer))$",
    re.IGNORECASE,
)
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

        targets: list[str] = []
        authorities: list[str] = []
        commitment_fields: list[str] = []
        amounts: list[str] = []
        assets: list[str] = []
        for field_match in _ADDRESS_FIELD_RE.finditer(body):
            field = field_match.group("field")
            if _TARGET_FIELD_NAME_RE.search(field):
                targets.append(field)
            if _AUTHORITY_NAME_RE.search(field):
                authorities.append(field)
            if _ASSET_NAME_RE.search(field):
                assets.append(field)
            if _COMMITMENT_FIELD_NAME_RE.search(field):
                commitment_fields.append(field)
        for field_match in _UINT_FIELD_RE.finditer(body):
            field = field_match.group("field")
            if _AMOUNT_NAME_RE.search(field):
                amounts.append(field)
            if _COMMITMENT_FIELD_NAME_RE.search(field):
                commitment_fields.append(field)
        for field_match in _BYTES_FIELD_RE.finditer(body):
            field = field_match.group("field")
            if _COMMITMENT_FIELD_NAME_RE.search(field):
                commitment_fields.append(field)

        out[match.group("name")] = StructShape(
            targets=_dedupe(targets),
            authorities=_dedupe(authorities),
            commitment_fields=_dedupe(commitment_fields),
            amounts=_dedupe(amounts),
            assets=_dedupe(assets),
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


def _local_struct_aliases(fn: FunctionSlice, shapes: dict[str, StructShape]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for match in _STRUCT_PARAM_RE.finditer(fn.body):
        type_name = match.group("type")
        if type_name in shapes:
            aliases[match.group("name")] = type_name
    return aliases


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
    for match in _INDEXED_REF_RE.finditer(text):
        field = match.group("field")
        if name_re.search(field) or name_re.search(field.strip("_")):
            refs.append(match.group(0))

    for param_name, type_name in _struct_params(fn, shapes).items():
        for field in getattr(shapes[type_name], shape_attr):
            refs.append(f"{param_name}.{field}")
    for alias_name, type_name in _local_struct_aliases(fn, shapes).items():
        for field in getattr(shapes[type_name], shape_attr):
            refs.append(f"{alias_name}.{field}")
    return _dedupe(refs)


def _address_params_by_name(fn: FunctionSlice, name_re: re.Pattern[str]) -> list[str]:
    refs: list[str] = []
    for match in _ADDRESS_PARAM_RE.finditer(fn.header):
        name = match.group("name")
        if name_re.search(name) or name_re.search(name.strip("_")):
            refs.append(name)
    return _dedupe(refs)


def _uint_params_by_name(fn: FunctionSlice, name_re: re.Pattern[str]) -> list[str]:
    refs: list[str] = []
    for match in _UINT_PARAM_RE.finditer(fn.header):
        name = match.group("name")
        if name_re.search(name) or name_re.search(name.strip("_")):
            refs.append(name)
    return _dedupe(refs)


def _sink_params(fn: FunctionSlice) -> list[str]:
    return _address_params_by_name(fn, _SINK_PARAM_NAME_RE)


def _target_sources(fn: FunctionSlice, shapes: dict[str, StructShape]) -> list[str]:
    return _dedupe(
        _field_refs_by_name(fn, _TARGET_FIELD_NAME_RE, shapes, "targets")
        + _field_refs_by_name(fn, _AUTHORITY_NAME_RE, shapes, "authorities")
    )


def _amount_sources(fn: FunctionSlice, shapes: dict[str, StructShape]) -> list[str]:
    return _dedupe(
        _uint_params_by_name(fn, _AMOUNT_NAME_RE)
        + _field_refs_by_name(fn, _AMOUNT_NAME_RE, shapes, "amounts")
    )


def _asset_sources(fn: FunctionSlice, shapes: dict[str, StructShape]) -> list[str]:
    return _dedupe(
        _address_params_by_name(fn, _ASSET_NAME_RE)
        + _field_refs_by_name(fn, _ASSET_NAME_RE, shapes, "assets")
    )


def _commitment_sources(fn: FunctionSlice, shapes: dict[str, StructShape]) -> list[str]:
    return _dedupe(_field_refs_by_name(fn, _COMMITMENT_FIELD_NAME_RE, shapes, "commitment_fields"))


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


def _condition_binds_sink(expr: str, sink: str, expected_sources: list[str]) -> bool:
    norm = _normalise_expr(expr)
    norm_sink = _normalise_expr(sink)
    if norm_sink not in norm:
        return False
    without_zero = norm.replace("address(0)", "")
    if norm_sink not in without_zero:
        return False
    if not any(source and source in without_zero for source in expected_sources):
        return False
    lowered = without_zero.lower()
    return (
        "==" in without_zero
        or "!=" in without_zero
        or _ALLOWLIST_WORD_RE.search(lowered) is not None
    )


def _hash_or_verify_binds_sink(body: str, sink: str) -> bool:
    norm_sink = _normalise_expr(sink)
    for match in _HASH_BINDING_CALL_RE.finditer(body):
        if norm_sink in _normalise_expr(match.group("args")):
            return True
    return False


def _validator_binds_sink(body: str, sink: str, expected_sources: list[str]) -> bool:
    norm_sink = _normalise_expr(sink)
    for match in _VALIDATOR_RE.finditer(body):
        args = _normalise_expr(match.group("args"))
        if norm_sink not in args:
            continue
        if any(source and source in args for source in expected_sources):
            return True
    return False


def _has_binding_guard(body: str, sink: str, expected_sources: list[str]) -> bool:
    if _hash_or_verify_binds_sink(body, sink):
        return True

    norm_sink = _normalise_expr(sink)
    expected_aliases = _assignment_aliases(body, expected_sources)
    if norm_sink in expected_aliases:
        return True

    for match in _CONDITION_RE.finditer(body):
        expr = match.group("expr")
        if not _condition_binds_sink(expr, sink, expected_sources):
            continue
        if match.group(0).lower().startswith("if"):
            tail = body[match.end():match.end() + 240]
            if _REVERT_WORD_RE.search(expr + tail):
                return True
        else:
            return True

    return _validator_binds_sink(body, sink, expected_sources)


def _has_order_settlement_context(
    fn: FunctionSlice,
    target_sources: list[str],
    amount_sources: list[str],
    commitment_sources: list[str],
) -> bool:
    text = fn.header + "\n" + fn.body
    if not _FLOW_CONTEXT_RE.search(fn.name) and not _FLOW_CONTEXT_RE.search(text):
        return False
    if _COMMITMENT_CONTEXT_RE.search(text):
        return True
    if target_sources and amount_sources:
        return True
    return bool(commitment_sources)


def _sink_is_asset_or_amount(sink: str, asset_sources: list[str], amount_sources: list[str]) -> bool:
    return sink in set(asset_sources) or sink in set(amount_sources)


def _match_function(
    fn: FunctionSlice,
    shapes: dict[str, StructShape],
) -> tuple[str, str, ValueEdge] | None:
    if not _CALLABLE_HEADER_RE.search(fn.header):
        return None
    if _PRIVILEGED_HEADER_RE.search(fn.header):
        return None
    if not _VALUE_CONTEXT_RE.search(fn.body):
        return None

    sink_params = _sink_params(fn)
    target_sources = _target_sources(fn, shapes)
    amount_sources = _amount_sources(fn, shapes)
    asset_sources = _asset_sources(fn, shapes)
    commitment_sources = _commitment_sources(fn, shapes)
    if not _has_order_settlement_context(fn, target_sources, amount_sources, commitment_sources):
        return None

    sink_aliases = _assignment_aliases(fn.body, sink_params)
    expected_sources = _dedupe(target_sources + sink_params)
    edges = [
        edge
        for edge in _collect_transfer_edges(fn.body)
        if not _is_inbound_pull(edge) and not _is_refundish_edge(edge)
    ]

    for edge in edges:
        sink = _normalise_expr(edge.sink)
        if not sink or _sink_is_asset_or_amount(sink, asset_sources, amount_sources):
            continue

        if sink in sink_aliases:
            field_expectations = [source for source in target_sources if source != sink]
            if _has_binding_guard(fn.body, sink, field_expectations):
                continue
            return (
                sink,
                "calldata settlement recipient is not bound to the signed, proof, escrow, or stored target",
                edge,
            )

        if _HARDCODED_SINK_RE.search(sink) and target_sources:
            field_expectations = [source for source in expected_sources if source != sink]
            if _has_binding_guard(fn.body, sink, field_expectations):
                continue
            return (
                sink,
                "hardcoded settlement sink is not bound to the canonical order, proof, escrow, or stored target",
                edge,
            )

    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean_source = _strip_comments(source)
    shapes = _struct_shapes(clean_source)
    findings: list[Finding] = []
    for fn in _split_functions(clean_source):
        matched = _match_function(fn, shapes)
        if matched is None:
            continue
        sink, reason, edge = matched
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn, edge.anchor),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` {edge.reason}, but {reason}; sink `{sink}`. "
                    "Bind recipient, owner, maker, taker, beneficiary, or account "
                    "to the signed order, claim proof, escrow owner, or stored "
                    "settlement target before value movement. NOT_SUBMIT_READY: "
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
