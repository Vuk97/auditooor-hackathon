"""
fund_loss_state_asymmetry_fire13.py

Flags Rust accounting paths where arithmetic state and value-moving behavior
can drift apart. This is a narrow recall-lift detector for the
fund-loss-via-arithmetic class:

1. add/remove style paired functions where the positive path increments an
   accounting storage key and the negative path does not touch the same key.
2. claim/redeem/distribute paths that move value before setting a consumed or
   claimed marker.
3. same-function double subtraction of the same accounting operand.

This is detector-fixture smoke only. It is not finding evidence.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    functions_in_contractimpl,
    is_pub,
    line_col,
    snippet_of,
)


_PAIR_PREFIXES = [
    ("add_", "remove_"),
    ("enable_", "disable_"),
    ("grant_", "revoke_"),
    ("register_", "deregister_"),
    ("stake_", "unstake_"),
    ("deposit_", "withdraw_"),
    ("mint_", "burn_"),
    ("credit_", "claim_"),
    ("accrue_", "claim_"),
    ("allocate_", "deallocate_"),
    ("fund_", "release_"),
]

_ARITH_ADD_RE = re.compile(
    r"(?i)(\+=|checked_add\s*\(|saturating_add\s*\(|wrapping_add\s*\(|"
    r"unwrap_or\s*\(\s*0\s*\)\s*\+|\+\s*\d+|\+\s*[A-Za-z_][A-Za-z0-9_]*)"
)
_ACCOUNTING_KEY_RE = re.compile(
    r"(?i)(count|balance|balances|reserve|reserves|reward|rewards|claim|"
    r"claimed|credit|credits|pending|owed|debt|share|shares|stake|stakes|"
    r"supply|escrow|allowance|allocation|entitlement|amount)"
)
_VALUE_MOVE_RE = re.compile(
    r"(?i)(\.transfer\s*\(|::transfer\s*\(|token::transfer\s*\(|"
    r"\.try_transfer\s*\(|\.mint_to\s*\(|\.send\s*\(|pay_out\s*\(|"
    r"payout\s*\(|release_funds\s*\(|credit_to_user\s*\()"
)
_CLAIM_FN_RE = re.compile(
    r"(?i)^(claim|claim_[A-Za-z0-9_]*|redeem|redeem_[A-Za-z0-9_]*|"
    r"distribute|withdraw|withdraw_[A-Za-z0-9_]*|release|collect)$"
)
_CONSUME_RE = re.compile(
    r"(?i)(set_claim(ed)?\s*\(|mark_claim(ed)?\s*\(|"
    r"set_(claimed|consumed|redeemed|processed)\s*\(|"
    r"mark_(claimed|consumed|redeemed|processed)\s*\(|"
    r"(claimed|consumed|redeemed|processed)[A-Za-z0-9_]*\s*=\s*(true|1)|"
    r"\.set\s*\([^;]*(Claim|Claimed|Redeemed|Processed)[^;]*(true|1)|"
    r"\.remove\s*\(|\.take\s*\(|\.set\s*\([^;]+,\s*&?0(?:[iu]\d+)?|"
    r"\.insert\s*\([^;]+,\s*&?0(?:[iu]\d+)?|-=|checked_sub\s*\(|"
    r"saturating_sub\s*\(|wrapping_sub\s*\(|"
    r"clear_[A-Za-z0-9_]*\s*\(|debit_[A-Za-z0-9_]*\s*\(|"
    r"deduct_[A-Za-z0-9_]*\s*\(|consume_[A-Za-z0-9_]*\s*\(|"
    r"reset_[A-Za-z0-9_]*\s*\()"
)
_DOUBLE_SUB_EXPR_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;\n]*-\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*-\s*\2\b"
)
_DOUBLE_SUB_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*-=\s*([A-Za-z_][A-Za-z0-9_]*)"
    r"[\s\S]{0,240}?\b\1\s*-=\s*\2\b"
)


def _storage_keys(body_text: str) -> set[str]:
    keys: set[str] = set()
    for raw in re.findall(r'Symbol::new\s*\([^,]+,\s*"([^"]+)"\s*\)', body_text):
        keys.add(f"symbol:{raw.lower()}")
    for raw in re.findall(r'symbol_short!\s*\(\s*"([^"]+)"\s*\)', body_text):
        keys.add(f"symbol:{raw.lower()}")
    for raw in re.findall(r"DataKey::([A-Za-z_][A-Za-z0-9_]*)", body_text):
        keys.add(f"datakey:{raw.lower()}")
    for raw in re.findall(r'"([^"]+)"', body_text):
        if _ACCOUNTING_KEY_RE.search(raw):
            keys.add(f"string:{raw.lower()}")
    return keys


def _accounting_keys(keys: set[str]) -> set[str]:
    return {key for key in keys if _ACCOUNTING_KEY_RE.search(key)}


def _consume_before_value_move(body_text: str) -> bool:
    value_match = _VALUE_MOVE_RE.search(body_text)
    if value_match is None:
        return True
    consume_match = _CONSUME_RE.search(body_text)
    return consume_match is not None and consume_match.start() < value_match.start()


def _double_sub_operand(body_text: str) -> str | None:
    match = _DOUBLE_SUB_EXPR_RE.search(body_text)
    if match is not None:
        operand = match.group(2)
        if _ACCOUNTING_KEY_RE.search(body_text) or _ACCOUNTING_KEY_RE.search(operand):
            return operand
    match = _DOUBLE_SUB_ASSIGN_RE.search(body_text)
    if match is not None:
        operand = match.group(2)
        if _ACCOUNTING_KEY_RE.search(body_text) or _ACCOUNTING_KEY_RE.search(operand):
            return operand
    return None


def _paired_name(name: str) -> tuple[str, str] | None:
    for positive, negative in _PAIR_PREFIXES:
        if name.startswith(positive):
            return negative + name[len(positive):], positive.rstrip("_")
    return None


def run(tree, source: bytes, filepath: str):
    hits = []
    by_impl: dict[int, dict[str, dict[str, object]]] = {}

    for fn, impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        name = fn_name(fn, source)
        by_impl.setdefault(id(impl), {})[name] = {
            "node": fn,
            "body": body_nc,
            "keys": _storage_keys(body_nc),
        }

        value_match = _VALUE_MOVE_RE.search(body_nc)
        if value_match is not None and _CLAIM_FN_RE.search(name):
            if not _consume_before_value_move(body_nc):
                line, col = line_col(fn)
                hits.append(
                    {
                        "severity": "high",
                        "line": line,
                        "col": col,
                        "snippet": snippet_of(fn, source, 180),
                        "message": (
                            f"pub fn `{name}` moves value before a claimed, "
                            f"consumed, or accounting reset marker is written. "
                            f"Fund-loss arithmetic state can be replayed "
                            f"(fund-loss-state-asymmetry-fire13)."
                        ),
                    }
                )

        operand = _double_sub_operand(body_nc)
        if operand is not None:
            line, col = line_col(fn)
            hits.append(
                {
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source, 180),
                    "message": (
                        f"pub fn `{name}` subtracts accounting operand "
                        f"`{operand}` twice from the same state calculation. "
                        f"Repeated subtraction can understate used funds or "
                        f"bypass limits (fund-loss-state-asymmetry-fire13)."
                    ),
                }
            )

    seen_pairs: set[tuple[str, str]] = set()
    for fns in by_impl.values():
        for name, meta in fns.items():
            paired = _paired_name(name)
            if paired is None:
                continue
            counterpart, verb = paired
            if counterpart not in fns:
                continue
            pair_key = tuple(sorted((name, counterpart)))
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            body_text = str(meta["body"])
            if not _ARITH_ADD_RE.search(body_text):
                continue
            positive_keys = _accounting_keys(set(meta["keys"]))
            negative_keys = _accounting_keys(set(fns[counterpart]["keys"]))
            if not positive_keys:
                continue
            missing = positive_keys - negative_keys
            if not missing:
                continue

            node = meta["node"]
            line, col = line_col(node)
            hits.append(
                {
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(node, source, 180),
                    "message": (
                        f"paired `{name}` / `{counterpart}` paths are "
                        f"arithmetic-asymmetric: `{name}` {verb}s accounting "
                        f"keys {sorted(missing)}, but `{counterpart}` does "
                        f"not unwind them. Fund-loss state can drift across "
                        f"paired lifecycle paths "
                        f"(fund-loss-state-asymmetry-fire13)."
                    ),
                }
            )

    return hits
