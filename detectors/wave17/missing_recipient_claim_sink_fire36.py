"""
missing-recipient-claim-sink-fire36

Regex API detector for Solidity claim, withdraw, redeem, refund, release, and
settle paths where a user supplied recipient is ignored, replaced by
msg.sender, replaced by a hardcoded sink, or not bound to the proof payload
recipient before value movement.

Source refs:
* reports/detector_lift_fire35_20260605/post_priorities_all.md
* reference/patterns.dsl/missing-recipient-validation-transfer-or-credit.yaml
* reference/patterns.dsl/withdraw-claim-recipient-ignored-hardcoded-sink.yaml
* reference/patterns.dsl/dh-odos-exchange-unset-toReceiver.yaml
* detectors/wave17/recipient_settlement_target_fire35.py
* detectors/wave17/recipient_struct_payout_sink_fire32.py

Detector hits are candidate evidence only. They are NOT_SUBMIT_READY and must
not be used as exploit proof without R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "missing-recipient-claim-sink-fire36"
DETECTOR_SEVERITY_DEFAULT = "Medium"
PROMOTION_ALLOWED = False
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"
SOURCE_REFS = (
    "reports/detector_lift_fire35_20260605/post_priorities_all.md",
    "reference/patterns.dsl/missing-recipient-validation-transfer-or-credit.yaml",
    "reference/patterns.dsl/withdraw-claim-recipient-ignored-hardcoded-sink.yaml",
    "reference/patterns.dsl/dh-odos-exchange-unset-toReceiver.yaml",
    "detectors/wave17/recipient_settlement_target_fire35.py",
    "detectors/wave17/recipient_struct_payout_sink_fire32.py",
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
    recipients: list[str]
    principals: list[str]
    tokens: list[str]
    amounts: list[str]
    proof_fields: list[str]


@dataclass
class ValueEdge:
    reason: str
    sink: str
    call_name: str
    args: list[str]
    anchor: re.Match[str]


@dataclass
class ProofCall:
    name: str
    args: list[str]
    anchor: re.Match[str]


_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_STRUCT_HEADER_RE = re.compile(r"\bstruct\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{")
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b", re.IGNORECASE)
_STRUCT_PARAM_RE = re.compile(
    r"\b(?P<type>[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"(?:calldata|memory|storage)?\s*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
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
_RECIPIENT_NAME_RE = re.compile(
    r"^(?:_?to|recipient|receiver|beneficiary|payee|payoutTo|payoutTarget|"
    r"payoutSink|settlementRecipient|settlementTarget|claimRecipient|"
    r"withdrawRecipient|refundTo|refundRecipient|releaseTo|redeemTo|"
    r"toReceiver|dstReceiver|destination|remoteRecipient|targetRecipient|"
    r"recipientAddress|receiverAddress)$",
    re.IGNORECASE,
)
_PRINCIPAL_NAME_RE = re.compile(
    r"^(?:_?owner|maker|sender|from|account|user|claimant|claimer|payer|"
    r"operator|executor|relayer|taker|seller|borrower|lender|benefactor)$",
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
    r"size|paymentAmount|bridgeAmount|claimAmount|withdrawAmount|"
    r"depositAmount|payoutAmount|creditAmount|proceeds|reward)$",
    re.IGNORECASE,
)
_PROOF_FIELD_NAME_RE = re.compile(
    r"(proof|merkle|root|leaf|digest|hash|signature|sig|nonce|claimId)",
    re.IGNORECASE,
)
_FLOW_NAME_RE = re.compile(
    r"^(?:claim|claimFees|claimReward|withdraw|redeem|settle|settlement|"
    r"refund|release|exit|bridgeExit|payout|payOut|collect|fill|execute)"
    r"[A-Za-z0-9_]*$",
    re.IGNORECASE,
)
_FLOW_CONTEXT_RE = re.compile(
    r"(claim|withdraw|redeem|settle|settlement|refund|release|exit|payout|"
    r"recipient|receiver|beneficiary|proof|merkle|leaf|root|amount|asset|token)",
    re.IGNORECASE,
)
_VALUE_CONTEXT_RE = re.compile(
    r"\b(safeTransferFrom|transferFrom|_transfer|safeTransfer|transfer|"
    r"sendValue|call\s*\{|_safeMint|_mint|mint|balances?\s*\[|credits?\s*\[|"
    r"claimable\s*\[|pending\s*\[|owed\s*\[|payouts?\s*\[|rewards?\s*\[)\b",
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
_PROOF_CALL_NAME_RE = re.compile(
    r"(verify|validate|check|proof|merkle|leaf|root|digest|hash|claim)",
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
    r"[A-Za-z0-9_]*(?:Recipient|Receiver|Beneficiary|Target|Sink|Payout|"
    r"Claim|Claimant|Account|Owner|Maker|Proof|Payload|Authority)"
    r"[A-Za-z0-9_]*\s*\((?P<args>[^;{}]*)\)",
    re.IGNORECASE | re.DOTALL,
)
_REVERT_WORD_RE = re.compile(
    r"(revert|RecipientMismatch|TargetMismatch|InvalidRecipient|InvalidReceiver|"
    r"InvalidTarget|BadRecipient|BadReceiver|NotRecipient|ZeroRecipient|"
    r"Unauthorized|NotOwner|WrongRecipient|ClaimantMismatch|PayloadMismatch|"
    r"ProofRecipientMismatch|NotAllowed)",
    re.IGNORECASE,
)
_ALLOWLIST_WORD_RE = re.compile(
    r"(allowed|approved|authorized|whitelist|canReceive|recipientAllowlist)",
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
_HARDCODED_DIRECT_RE = re.compile(
    r"^(?:msg\.sender|_msgSender\(\)|tx\.origin|owner\(\)|owner|"
    r"address\(this\)|this|vault|router|escrow|treasury|protocol|"
    r"settlementSink|payoutSink|defaultSink|defaultRecipient|storedSink|"
    r"feeReceiver|feeCollector|account|payer|operator|executor|relayer|"
    r"maker|sender|from|claimant|claimer|request\.account|request\.owner|"
    r"request\.sender|claim\.owner|claim\.account|claim\.claimant|"
    r"withdrawal\.account|withdrawal\.owner|position\.owner|order\.maker|"
    r"order\.sender|order\.owner|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?\.(?:maker|sender|from|owner|"
    r"account|claimant|claimer|payer|operator|executor|relayer|taker|seller|"
    r"borrower|lender))$",
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

        recipients: list[str] = []
        principals: list[str] = []
        tokens: list[str] = []
        amounts: list[str] = []
        proof_fields: list[str] = []
        for field_match in _ADDRESS_FIELD_RE.finditer(body):
            field = field_match.group("field")
            if _RECIPIENT_NAME_RE.search(field):
                recipients.append(field)
            if _PRINCIPAL_NAME_RE.search(field):
                principals.append(field)
            if _TOKEN_NAME_RE.search(field):
                tokens.append(field)
            if _PROOF_FIELD_NAME_RE.search(field):
                proof_fields.append(field)
        for field_match in _UINT_FIELD_RE.finditer(body):
            field = field_match.group("field")
            if _AMOUNT_NAME_RE.search(field):
                amounts.append(field)
            if _PROOF_FIELD_NAME_RE.search(field):
                proof_fields.append(field)
        for field_match in _BYTES_FIELD_RE.finditer(body):
            field = field_match.group("field")
            if _PROOF_FIELD_NAME_RE.search(field):
                proof_fields.append(field)

        out[match.group("name")] = StructShape(
            recipients=_dedupe(recipients),
            principals=_dedupe(principals),
            tokens=_dedupe(tokens),
            amounts=_dedupe(amounts),
            proof_fields=_dedupe(proof_fields),
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


def _recipient_sources(fn: FunctionSlice, shapes: dict[str, StructShape]) -> list[str]:
    return _dedupe(
        _address_params_by_name(fn, _RECIPIENT_NAME_RE)
        + _field_refs_by_name(fn, _RECIPIENT_NAME_RE, shapes, "recipients")
    )


def _payload_recipient_sources(fn: FunctionSlice, shapes: dict[str, StructShape]) -> list[str]:
    return [source for source in _field_refs_by_name(fn, _RECIPIENT_NAME_RE, shapes, "recipients") if "." in source]


def _principal_sources(fn: FunctionSlice, shapes: dict[str, StructShape]) -> list[str]:
    return _dedupe(
        _address_params_by_name(fn, _PRINCIPAL_NAME_RE)
        + _field_refs_by_name(fn, _PRINCIPAL_NAME_RE, shapes, "principals")
    )


def _token_sources(fn: FunctionSlice, shapes: dict[str, StructShape]) -> list[str]:
    return _dedupe(
        _address_params_by_name(fn, _TOKEN_NAME_RE)
        + _field_refs_by_name(fn, _TOKEN_NAME_RE, shapes, "tokens")
    )


def _amount_sources(fn: FunctionSlice, shapes: dict[str, StructShape]) -> list[str]:
    return _dedupe(
        _uint_params_by_name(fn, _AMOUNT_NAME_RE)
        + _field_refs_by_name(fn, _AMOUNT_NAME_RE, shapes, "amounts")
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


def _condition_binds_source_to_sink(expr: str, source: str, sink: str) -> bool:
    norm = _normalise_expr(expr)
    norm_source = _normalise_expr(source)
    norm_sink = _normalise_expr(sink)
    if norm_source not in norm or norm_sink not in norm:
        return False
    without_zero = norm.replace("address(0)", "")
    if norm_source not in without_zero or norm_sink not in without_zero:
        return False
    lowered = without_zero.lower()
    return (
        "==" in without_zero
        or "!=" in without_zero
        or _ALLOWLIST_WORD_RE.search(lowered) is not None
    )


def _has_binding_guard(body: str, source: str, sink: str) -> bool:
    for match in _CONDITION_RE.finditer(body):
        expr = match.group("expr")
        if not _condition_binds_source_to_sink(expr, source, sink):
            continue
        if match.group(0).lower().startswith("if"):
            tail = body[match.end():match.end() + 240]
            if _REVERT_WORD_RE.search(expr + tail):
                return True
        else:
            return True
    for match in _VALIDATOR_RE.finditer(body):
        args = _normalise_expr(match.group("args"))
        if _normalise_expr(source) in args and _normalise_expr(sink) in args:
            return True
    return False


def _collect_proof_calls(body: str) -> list[ProofCall]:
    calls: list[ProofCall] = []
    for match in _GENERAL_CALL_RE.finditer(body):
        name = match.group("name")
        args = _extract_call_args(body, match.end() - 1)
        arg_text = ",".join(args)
        if _PROOF_CALL_NAME_RE.search(name) or _PROOF_FIELD_NAME_RE.search(arg_text):
            calls.append(ProofCall(name=name, args=args, anchor=match))
    return calls


def _proof_calls_bind_recipient(
    body: str,
    sink: str,
    payload_recipients: list[str],
) -> bool:
    proof_calls = _collect_proof_calls(body)
    if not proof_calls:
        return False
    terms = [sink] + payload_recipients
    for call in proof_calls:
        args = _normalise_expr(",".join(call.args))
        if any(term and term in args for term in terms):
            return True
    return False


def _unbound_proof_payload_recipient(
    body: str,
    sink: str,
    payload_recipients: list[str],
) -> str | None:
    candidates = [source for source in payload_recipients if source != sink]
    if not candidates:
        return None
    if not _collect_proof_calls(body):
        return None
    for source in candidates:
        if _has_binding_guard(body, source, sink):
            return None
    if _proof_calls_bind_recipient(body, sink, candidates):
        return None
    return candidates[0]


def _has_claim_sink_context(
    fn: FunctionSlice,
    recipient_sources: list[str],
    amount_sources: list[str],
    principal_sources: list[str],
) -> bool:
    if _FLOW_NAME_RE.search(fn.name):
        return True
    text = fn.header + "\n" + fn.body
    if recipient_sources and amount_sources and _FLOW_CONTEXT_RE.search(text):
        return True
    if principal_sources and recipient_sources and _FLOW_CONTEXT_RE.search(text):
        return True
    return False


def _match_function(
    fn: FunctionSlice,
    shapes: dict[str, StructShape],
) -> tuple[str, str, str, ValueEdge] | None:
    if not _CALLABLE_HEADER_RE.search(fn.header):
        return None
    if _PRIVILEGED_HEADER_RE.search(fn.header):
        return None
    if not _VALUE_CONTEXT_RE.search(fn.body):
        return None

    recipient_sources = _recipient_sources(fn, shapes)
    if not recipient_sources:
        return None
    amount_sources = _amount_sources(fn, shapes)
    principal_sources = _principal_sources(fn, shapes)
    token_sources = _token_sources(fn, shapes)
    if not amount_sources:
        return None
    if not _has_claim_sink_context(fn, recipient_sources, amount_sources, principal_sources):
        return None

    edges = [
        edge
        for edge in _collect_transfer_edges(fn.body)
        if not _is_inbound_pull(edge) and not _is_refundish_edge(edge)
    ]
    if not edges:
        return None

    source_aliases, hardcoded_aliases, overwritten_sources = _assignment_facts(
        fn.body,
        recipient_sources,
    )
    payload_recipients = _payload_recipient_sources(fn, shapes)

    for edge in edges:
        sink = _normalise_expr(edge.sink)
        if sink in token_sources:
            continue

        if sink in source_aliases and sink not in overwritten_sources:
            unbound_payload = _unbound_proof_payload_recipient(
                fn.body,
                sink,
                payload_recipients,
            )
            if unbound_payload:
                return (
                    sink,
                    unbound_payload,
                    "recipient sink is not bound to proof payload recipient",
                    edge,
                )
            continue

        if any(_has_binding_guard(fn.body, source, sink) for source in recipient_sources):
            continue

        if sink in overwritten_sources:
            return (
                sink,
                recipient_sources[0],
                "recipient alias is overwritten before payout",
                edge,
            )

        if _is_hardcoded_sink(sink, hardcoded_aliases):
            return (
                sink,
                recipient_sources[0],
                "user supplied recipient is ignored in favor of a hardcoded claim sink",
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
        sink, recipient, reason, edge = matched
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn, edge.anchor),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` receives recipient-like value `{recipient}` but "
                    f"{edge.reason}; {reason} to `{sink}`. Bind the final claim, "
                    "withdraw, redeem, release, or settlement payout to the supplied "
                    "recipient, or prove an equality or allowlist guard before value "
                    "movement. NOT_SUBMIT_READY: detector fixture smoke only."
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
