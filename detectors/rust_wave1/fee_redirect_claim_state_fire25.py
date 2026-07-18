"""
fee_redirect_claim_state_fire25.py

Rust same-class lift for fee-redirect and fee-claim accounting misses.

Flags public value-moving fee, refund, claim, or harvest handlers when:
  1. a refund is computed from a post-fee amount instead of the pre-fee input,
  2. a fee claim or withdraw transfers value without consumed or claimed state,
  3. a fee or refund sink is caller supplied and not bound to protocol config,
  4. a fee harvest swap accepts amount_out_minimum or min_out equal to zero.

Seed provenance:
  - dsl_pattern/r94-loop-tax-refund-post-fee-amount
  - dsl_pattern/r94-loop-withdraw-fee-no-claimed-flag
  - Solodit 30948 StrategyPassiveManagerUniswap amountOutMinimum=0

Detector hits are candidate evidence only. They require source review and a
real PoC before use in any finding.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
    text_of,
)


_REFUND_NAME_RE = re.compile(r"(?i)(refund|rebate|reimburse|tax_refund|fee_refund)")

_FEE_OR_CLAIM_HANDLER_RE = re.compile(
    r"(?i)(claim|collect|withdraw|harvest|charge|refund|rebate|"
    r"fee|fees|protocol_fee|treasury_fee|performance_fee)"
)

_FEE_CONTEXT_RE = re.compile(
    r"(?i)\b[A-Za-z0-9_]*(?:fee|fees|refund|rebate|claim)"
    r"[A-Za-z0-9_]*\b|"
    r"\b(protocol_fee|platform_fee|treasury_fee|performance_fee|"
    r"harvest_fee|claim_amount|claimed_amount|accrued_fee|"
    r"fee_amount)\b"
)

_POST_FEE_RE = re.compile(
    r"(?i)\b(amount_after_fee|amt_post_fee|post_fee_amount|net_amount|"
    r"received_amount|transferred_amount|transferred|actual_received)\b|"
    r"(?:balance_of|balanceOf)\s*\([^)]*\)\s*-\s*"
    r"(?:balance_before|prev_balance|before_balance)|"
    r"\brefund\s*=\s*[A-Za-z_][A-Za-z0-9_]*after_fee\b"
)

_PRE_FEE_SAFE_RE = re.compile(
    r"(?i)\b(pre_fee|pre_fee_amount|input_amount|original_amount|"
    r"gross_amount|gross_input|amount_in_raw|requested_amount)\b"
)

_TRANSFER_OR_CREDIT_RE = re.compile(
    r"(?i)(?:\.[ \t]*)?(?:safe_transfer_from|transfer_from|safe_transfer|"
    r"transfer|send|credit|deposit_to|release_to|payout_to|mint_to)"
    r"\s*\("
)

_TRANSFER_CALL_RE = re.compile(
    r"(?i)(?:[A-Za-z_][A-Za-z0-9_\.]*\s*\.\s*)?"
    r"(?:safe_transfer_from|transfer_from|safe_transfer|transfer|send|"
    r"credit|deposit_to|release_to|payout_to|mint_to)\s*"
    r"\((?P<args>[^;]{0,360})\)"
)

_CONSUMED_STATE_RE = re.compile(
    r"(?i)("
    r"\b(?:claimed|claim_consumed|fee_claimed|refund_claimed|"
    r"refund_consumed|withdrawn|fee_withdrawn|paid|processed|used)\b"
    r"[^;\n]{0,140}(?:=\s*true|\.insert\s*\(|\.set\s*\(|"
    r"\.write\s*\(|\.remove\s*\()|"
    r"\b(?:mark|set|consume|record)_(?:claim|refund|fee|withdraw)"
    r"[A-Za-z0-9_]*"
    r"\s*\("
    r")"
)

_SINK_PARAM_NAME_RE = re.compile(
    r"(?i)^(fee_recipient|fee_receiver|recipient|receiver|beneficiary|"
    r"collector|collector_account|to|dst|destination|refund_recipient|"
    r"claim_recipient|treasury|payout_account)$"
)

_SINK_PARAM_TYPE_RE = re.compile(
    r"(?i)\b(Address|AccountId|Pubkey|PublicKey|AccountInfo|Account|H160|"
    r"Principal|u64|u128)\b"
)

_BINDING_WORD_RE = re.compile(
    r"(?i)(assert|assert_eq|ensure|require|check|validate|must_match|"
    r"expected|configured|allowed|authorized|has_one)"
)

_CONFIG_ANCHOR_RE = re.compile(
    r"(?i)(self\.[A-Za-z0-9_\.]*(?:fee_recipient|fee_receiver|collector|"
    r"treasury|beneficiary)|config(?:ured|uration)?[A-Za-z0-9_\.]*"
    r"(?:fee_recipient|fee_receiver|collector|treasury|beneficiary)|"
    r"protocol_(?:fee_recipient|collector|treasury)|"
    r"expected_(?:fee_recipient|collector|treasury)|"
    r"fee_recipient_for\s*\()"
)

_SWAP_CALL_RE = re.compile(
    r"(?i)(\.swap\s*\(|::swap\s*\(|\bswap\s*\(|\.exact_input\s*\(|"
    r"\.exact_output\s*\(|swap_exact_tokens_for_tokens\s*\(|"
    r"router\s*\.\s*\w*swap\s*\()"
)

_ZERO_MIN_OUT_RE = re.compile(
    r"(?i)\b(amount_out_minimum|min_out|min_amount_out|amountOutMinimum|"
    r"amountOutMin)\s*:\s*0\b|"
    r"\b(amount_out_minimum|min_out|min_amount_out|amountOutMinimum|"
    r"amountOutMin)\s*=\s*0\b"
)

_NONZERO_MIN_OUT_RE = re.compile(
    r"(?i)\b(amount_out_minimum|min_out|min_amount_out|amountOutMinimum|"
    r"amountOutMin)\s*:\s*(?!0\b)[A-Za-z_][A-Za-z0-9_\.]*|"
    r"\b(expected_out|min_expected|slippage|oracle_out)\b"
)


def _split_args(args_text: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in args_text:
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth > 0:
            depth -= 1
    if current or args_text.strip():
        args.append("".join(current).strip())
    return args


def _sink_params(fn_text: str) -> set[str]:
    head = fn_text.split("{", 1)[0]
    match = re.search(r"\bfn\s+\w+\s*\((?P<params>.*?)\)", head, re.S)
    if not match:
        return set()

    params: set[str] = set()
    for param in _split_args(match.group("params")):
        name_match = re.match(r"\s*(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:", param)
        if not name_match:
            continue
        name = name_match.group(1)
        if _SINK_PARAM_NAME_RE.match(name) or (
            _SINK_PARAM_NAME_RE.search(name) and _SINK_PARAM_TYPE_RE.search(param)
        ):
            params.add(name)
    return params


def _mentions_term(text: str, term: str) -> bool:
    return re.search(r"(?<![\w.])" + re.escape(term) + r"(?![\w.])", text) is not None


def _has_bound_sink(body: str, params: set[str]) -> bool:
    for line in body.splitlines():
        if not _BINDING_WORD_RE.search(line):
            continue
        if not _CONFIG_ANCHOR_RE.search(line):
            continue
        if any(_mentions_term(line, param) for param in params):
            return True
    return False


def _transfer_to_unbound_fee_sink(body: str, params: set[str]) -> bool:
    if not params or _has_bound_sink(body, params):
        return False

    for match in _TRANSFER_CALL_RE.finditer(body):
        args = _split_args(match.group("args"))
        if not args:
            continue
        if not any(any(_mentions_term(arg, param) for param in params) for arg in args[:2]):
            continue
        window = body[max(0, match.start() - 160): match.end() + 160]
        if _FEE_CONTEXT_RE.search(window) or any(_FEE_CONTEXT_RE.search(arg) for arg in args):
            return True
    return False


def _post_fee_refund_hit(name: str, body: str) -> str | None:
    if not (_REFUND_NAME_RE.search(name) or _REFUND_NAME_RE.search(body)):
        return None
    if _POST_FEE_RE.search(body) and not _PRE_FEE_SAFE_RE.search(body):
        return (
            "refund amount is derived from post-fee received or balance-delta "
            "state instead of the pre-fee input amount"
        )
    return None


def _repeatable_claim_hit(name: str, body: str) -> str | None:
    if not _FEE_OR_CLAIM_HANDLER_RE.search(name):
        return None
    if not (_FEE_CONTEXT_RE.search(name) or _FEE_CONTEXT_RE.search(body)):
        return None
    if not _TRANSFER_OR_CREDIT_RE.search(body):
        return None
    if _CONSUMED_STATE_RE.search(body):
        return None
    return "fee or refund claim transfers value without consumed or claimed state"


def _unbound_fee_sink_hit(fn_text: str, body: str) -> str | None:
    params = _sink_params(fn_text)
    if not _transfer_to_unbound_fee_sink(body, params):
        return None
    return "fee or refund value is routed to a caller-supplied sink without binding it to protocol config"


def _zero_min_fee_harvest_hit(name: str, body: str) -> str | None:
    if not _FEE_OR_CLAIM_HANDLER_RE.search(name):
        return None
    if not _SWAP_CALL_RE.search(body):
        return None
    if _ZERO_MIN_OUT_RE.search(body) and not _NONZERO_MIN_OUT_RE.search(body):
        return "fee harvest swap uses zero minimum output"
    return None


def _reason_for_hit(fn_text: str, name: str, body: str) -> str | None:
    return (
        _post_fee_refund_hit(name, body)
        or _repeatable_claim_hit(name, body)
        or _unbound_fee_sink_hit(fn_text, body)
        or _zero_min_fee_harvest_hit(name, body)
    )


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source) or not is_pub(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        body_nc = body_text_nocomment(body, source)
        reason = _reason_for_hit(text_of(fn, source), name, body_nc)
        if reason is None:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"pub fn `{name}` has fee-redirect or fee-claim "
                    f"accounting risk: {reason}. Bind the fee recipient, "
                    "record claimed or consumed state before value movement, "
                    "compute refunds from the pre-fee basis, and enforce "
                    "nonzero fee-harvest slippage protection."
                ),
            }
        )
    return hits
