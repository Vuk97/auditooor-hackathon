"""
order-match-hardcoded-maker-sink-fire29

Regex API detector for order match, settlement, claim, or payout paths that
accept or imply a user-selected recipient but route exchange-held assets to a
hardcoded maker, caller, cached sink, or contract sink.

Source refs:
* reference/patterns.dsl/missing-recipient-validation-transfer-or-credit.yaml
* reference/patterns.dsl/withdraw-claim-recipient-ignored-hardcoded-sink.yaml
* reference/patterns.dsl/perp-liquidation-unwrap-native-ignores-cross-chain-recipient.yaml

Detector hits are candidate evidence only. They are NOT_SUBMIT_READY and must
not be used as exploit proof without R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "order-match-hardcoded-maker-sink-fire29"
DETECTOR_SEVERITY_DEFAULT = "Medium"
PROMOTION_ALLOWED = False
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
SOURCE_REFS = (
    "reference/patterns.dsl/missing-recipient-validation-transfer-or-credit.yaml",
    "reference/patterns.dsl/withdraw-claim-recipient-ignored-hardcoded-sink.yaml",
    "reference/patterns.dsl/perp-liquidation-unwrap-native-ignores-cross-chain-recipient.yaml",
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


_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b", re.IGNORECASE)
_SKIP_RE = re.compile(r"\b(?:mock|test|fixture|harness|example|demo)\b", re.IGNORECASE)

_ORDER_CONTEXT_RE = re.compile(
    r"\b(order|orders|match|matched|fill|filled|settle|settlement|claim|"
    r"payout|pay|refund|redeem|withdraw|transfer|trade|swap|execute|"
    r"taker|maker|router|exchange|escrow|proceeds|surplus|leftover)\b",
    re.IGNORECASE,
)
_ORDER_EXECUTION_RE = re.compile(
    r"\b(_fillMakerOrders?|_fillOrder|_executeMatchCall|_matchOrders?|"
    r"_settleOrder|_claimOrder|hashOrder|verifyOrder|validateOrder|"
    r"OrderMatched|OrdersMatched|OrderFilled|takerOrder|makerOrders?|"
    r"makerFillAmounts?|takerFillAmount)\b",
    re.IGNORECASE,
)
_VALUE_CONTEXT_RE = re.compile(
    r"\b(_transfer|safeTransfer|transferFrom|safeTransferFrom|transfer|"
    r"sendValue|call\s*\{|mint|_mint|balances?\s*\[|credits?\s*\[|"
    r"claimable\s*\[|payouts?\s*\[|proceeds|surplus|refund|leftover|"
    r"amountOut|taking\s*-\s*fee)\b",
    re.IGNORECASE,
)
_RECIPIENT_PARAM_RE = re.compile(
    r"\baddress(?:\s+payable)?\s+"
    r"(?P<name>recipient|receiver|to|beneficiary|payoutSink|payoutTo|"
    r"refundTo|refundRecipient|settlementRecipient|claimRecipient|"
    r"tradeRecipient|fillRecipient|user|account|maker|taker)\b",
    re.IGNORECASE,
)
_STRUCT_FIELD_RE = re.compile(
    r"\b(?P<root>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<field>recipient|receiver|beneficiary|payoutTo|refundTo|"
    r"settlementRecipient|claimRecipient|tradeRecipient|fillRecipient|"
    r"expectedRecipient|userRecipient|takerRecipient)\b",
    re.IGNORECASE,
)
_SAFE_RECIPIENT_NAME_RE = re.compile(
    r"\b(?:recipient|receiver|beneficiary|payoutSink|payoutTo|refundTo|"
    r"settlementRecipient|claimRecipient|tradeRecipient|fillRecipient)\b",
    re.IGNORECASE,
)
_HARDCODED_SINK_RE = re.compile(
    r"^(?:"
    r"msg\.sender|_msgSender\(\)|tx\.origin|address\(this\)|this|"
    r"owner\(\)|treasury|feeReceiver|settlementSink|payoutSink|defaultSink|"
    r"defaultRecipient|cachedMaker|cachedTaker|cachedRecipient|cachedSink|"
    r"maker|taker|operator|relayer|executor|router|exchange|escrow|vault|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?\.(?:maker|taker|owner|account|router|vault|escrow)"
    r")$",
    re.IGNORECASE,
)
_COMPARISON_RE = re.compile(
    r"(?is)(?P<a>[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?|"
    r"msg\.sender|_msgSender\s*\(\s*\)|address\s*\(\s*this\s*\))"
    r"\s*(?:==|!=)\s*"
    r"(?P<b>[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?|"
    r"msg\.sender|_msgSender\s*\(\s*\)|address\s*\(\s*this\s*\))"
)
_VALIDATOR_CALL_RE = re.compile(
    r"\b(?:validate|check|assert|bind|verify)[A-Za-z0-9_]*"
    r"(?:Recipient|Receiver|Beneficiary|Payout|Sink|Settlement|Maker|Taker)"
    r"[A-Za-z0-9_]*\s*\((?P<args>[^;{}]*)\)",
    re.IGNORECASE | re.DOTALL,
)
_SELF_SETTLEMENT_GUARD_RE = re.compile(
    r"(?is)(?:require|if)\s*\([^;{}]*"
    r"(?:msg\.sender|_msgSender\s*\(\s*\))\s*(?:==|!=)\s*"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?(?:maker|taker|owner)"
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
    return re.sub(r"\s+", "", expr or "")


def _expr_regex(expr: str) -> str:
    return r"\s*\.\s*".join(re.escape(part) for part in _normalise_expr(expr).split("."))


def _recipient_atoms(fn: FunctionSlice) -> list[str]:
    atoms: list[str] = []
    for match in _RECIPIENT_PARAM_RE.finditer(fn.header):
        name = _normalise_expr(match.group("name"))
        if name not in atoms:
            atoms.append(name)
    for match in _STRUCT_FIELD_RE.finditer(fn.header + fn.body):
        atom = _normalise_expr(f"{match.group('root')}.{match.group('field')}")
        if atom not in atoms:
            atoms.append(atom)
    return atoms


def _explicit_recipient_atoms(atoms: list[str]) -> list[str]:
    return [atom for atom in atoms if _SAFE_RECIPIENT_NAME_RE.search(atom)]


def _value_sinks(body: str) -> list[tuple[str, str, re.Match[str]]]:
    sink_expr = (
        r"(?:msg\.sender|_msgSender\s*\(\s*\)|tx\.origin|address\s*\(\s*this\s*\)|"
        r"this|owner\s*\(\s*\)|[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\])?"
        r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?)"
    )
    patterns: list[tuple[str, str]] = [
        (
            "routes exchange-held order proceeds to a hardcoded sink",
            rf"\b_transfer\s*\(\s*address\s*\(\s*this\s*\)\s*,\s*(?P<sink>{sink_expr})\s*,",
        ),
        (
            "routes token payout to a hardcoded sink",
            rf"\b(?:safeTransfer|transfer|sendValue|mint|_mint)\s*\(\s*(?P<sink>{sink_expr})\s*,",
        ),
        (
            "routes escrowed token payout to a hardcoded sink",
            rf"\b(?:safeTransferFrom|transferFrom)\s*\(\s*address\s*\(\s*this\s*\)\s*,\s*"
            rf"(?P<sink>{sink_expr})\s*,",
        ),
        (
            "routes native payout to a hardcoded sink",
            rf"\bpayable\s*\(\s*(?P<sink>{sink_expr})\s*\)\s*\.\s*(?:transfer|send|call)\b",
        ),
        (
            "routes native payout to a hardcoded sink",
            rf"\b(?P<sink>{sink_expr})\s*\.\s*call\s*\{{\s*value\s*:",
        ),
        (
            "credits a hardcoded settlement sink",
            rf"\b(?:balances?|credits?|claimable|payouts?|proceeds)\s*\[\s*(?P<sink>{sink_expr})\s*\]\s*(?:\+=|=)",
        ),
    ]
    out: list[tuple[str, str, re.Match[str]]] = []
    for reason, pattern in patterns:
        for match in re.finditer(pattern, body, flags=re.IGNORECASE | re.DOTALL):
            out.append((reason, _normalise_expr(match.group("sink")), match))
    return out


def _sink_is_recipient_bound(sink: str, atoms: list[str]) -> bool:
    norm_sink = _normalise_expr(sink)
    return norm_sink in {_normalise_expr(atom) for atom in atoms}


def _sink_assigned_from_recipient(body: str, sink: str, atoms: list[str]) -> bool:
    sink_pattern = _expr_regex(sink)
    for atom in atoms:
        atom_pattern = _expr_regex(atom)
        assign_from_atom = (
            rf"(?is)\b(?:address(?:\s+payable)?\s+)?{sink_pattern}\s*=\s*{atom_pattern}\b"
        )
        assign_to_atom = (
            rf"(?is)\b(?:address(?:\s+payable)?\s+)?{atom_pattern}\s*=\s*{sink_pattern}\b"
        )
        if re.search(assign_from_atom, body) or re.search(assign_to_atom, body):
            return True
    return False


def _has_comparison_binding(body: str, sink: str, atoms: list[str]) -> bool:
    norm_sink = _normalise_expr(sink)
    atom_set = {_normalise_expr(atom) for atom in atoms}
    for match in _COMPARISON_RE.finditer(body):
        a = _normalise_expr(match.group("a"))
        b = _normalise_expr(match.group("b"))
        if a == norm_sink and b in atom_set:
            return True
        if b == norm_sink and a in atom_set:
            return True
    for match in _VALIDATOR_CALL_RE.finditer(body):
        args = _normalise_expr(match.group("args"))
        if norm_sink in args and any(atom in args for atom in atom_set):
            return True
    return False


def _is_hardcoded_sink(sink: str) -> bool:
    norm = _normalise_expr(sink)
    if _SAFE_RECIPIENT_NAME_RE.search(norm):
        return False
    return bool(_HARDCODED_SINK_RE.search(norm))


def _has_order_context(fn: FunctionSlice) -> bool:
    text = fn.header + "\n" + fn.body
    if not _ORDER_CONTEXT_RE.search(fn.name) and not _ORDER_CONTEXT_RE.search(text):
        return False
    if _ORDER_EXECUTION_RE.search(text) or re.search(r"\bOrder\b", fn.header):
        return True
    if _RECIPIENT_PARAM_RE.search(fn.header) and re.search(
        r"(?i)^(claim|claim[A-Z]|payout|pay|refund|release|withdraw|redeem|transfer|settle)"
        r"[A-Za-z0-9_]*$",
        fn.name,
    ):
        return True
    return False


def _match_function(fn: FunctionSlice) -> tuple[str, str, re.Match[str]] | None:
    if not _CALLABLE_HEADER_RE.search(fn.header):
        return None
    if not _has_order_context(fn):
        return None
    if not _VALUE_CONTEXT_RE.search(fn.body):
        return None

    atoms = _recipient_atoms(fn)
    explicit_recipient_atoms = _explicit_recipient_atoms(atoms)
    sinks = _value_sinks(fn.body)
    if not sinks:
        return None

    for reason, sink, anchor in sinks:
        if _sink_is_recipient_bound(sink, atoms):
            continue
        if not _is_hardcoded_sink(sink):
            continue
        if _sink_assigned_from_recipient(fn.body, sink, atoms):
            continue
        if _has_comparison_binding(fn.body, sink, atoms):
            continue
        if not explicit_recipient_atoms and _SELF_SETTLEMENT_GUARD_RE.search(fn.body):
            continue
        evidence = explicit_recipient_atoms[0] if explicit_recipient_atoms else "missing explicit recipient sink"
        return evidence, f"{reason} `{sink}`", anchor

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
        recipient_evidence, reason, anchor = matched
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn, anchor),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` has recipient evidence `{recipient_evidence}` but {reason}. "
                    "Bind every order-match payout, refund, claim, and credit edge to the "
                    "explicit recipient or assert maker-self settlement before value movement. "
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
