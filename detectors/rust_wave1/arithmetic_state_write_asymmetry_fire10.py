"""
arithmetic_state_write_asymmetry_fire10.py

Flags paired Rust/Soroban accounting paths where one public path credits or
increments state and a sibling claim / withdraw / redeem path moves value from
the same accounting bucket without clearing, decrementing, or consuming the
state first.

Anchors:
  - paired_function_state_write_asymmetry.py catches same-stem write-set drift.
  - r94_loop_airdrop_double_claim.py catches single claim functions with no
    claimed flag.
  - Solodit #47680 and #65323 records in the local corpus cover double-claim
    escrow / airdrop classes. This detector is the Rust lift for paired
    arithmetic accounting state.

This is a detector-fixture smoke heuristic. It is not submission evidence by
itself.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    functions_in_contractimpl,
    fn_body,
    fn_name,
    is_pub,
    line_col,
    snippet_of,
)


_CREDIT_NAME_RE = re.compile(
    r"(?i)(credit|deposit|accrue|add|grant|stake|mint|record|allocate|fund)"
)
_SPEND_NAME_RE = re.compile(
    r"(?i)(claim|withdraw|redeem|remove|unstake|burn|close|revert|settle|"
    r"payout|release|collect)"
)

_ACCOUNTING_WORD_RE = re.compile(
    r"(?i)(reward|credit|balance|claimable|owed|pending|escrow|deposit|"
    r"share|stake|accrued|allowance|entitlement|allocation)"
)
_IDENT_TOKEN_RE = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:reward|rewards|credit|credits|balance|"
    r"balances|claimable|owed|pending|escrow|deposit|deposits|share|shares|"
    r"stake|stakes|accrued|allowance|entitlement|allocation)[A-Za-z0-9_]*\b",
    re.IGNORECASE,
)
_STRING_TOKEN_RE = re.compile(r'"([^"]+)"')
_DATAKEY_RE = re.compile(r"DataKey::([A-Za-z_][A-Za-z0-9_]*)")

_STORAGE_WRITE_RE = re.compile(
    r"(?i)(\.set\s*\(|\.update\s*\(|\.insert\s*\(|storage\(\)\."
    r"(persistent|instance|temporary)\(\))"
)
_ARITH_CREDIT_RE = re.compile(
    r"(?i)(\+=|checked_add\s*\(|saturating_add\s*\(|wrapping_add\s*\(|"
    r"unwrap_or\s*\(\s*0\s*\)\s*\+|\+\s*[A-Za-z_][A-Za-z0-9_]*|"
    r"\+\s*\d+)"
)
_VALUE_MOVE_RE = re.compile(
    r"(?i)(\.transfer\s*\(|::transfer\s*\(|token::transfer\s*\(|"
    r"\.try_transfer\s*\(|\.mint_to\s*\(|pay_out\s*\(|payout\s*\(|"
    r"release_funds\s*\(|send\s*\(|credit_to_user\s*\()"
)
_CONSUME_RE = re.compile(
    r"(?i)(\.remove\s*\(|\.take\s*\(|\.set\s*\([^;]+,\s*&?0(?:[iu]\d+)?|"
    r"\.insert\s*\([^;]+,\s*&?0(?:[iu]\d+)?|-=|checked_sub\s*\(|"
    r"saturating_sub\s*\(|wrapping_sub\s*\(|clear_[A-Za-z0-9_]*\s*\(|"
    r"debit_[A-Za-z0-9_]*\s*\(|deduct_[A-Za-z0-9_]*\s*\(|"
    r"consume_[A-Za-z0-9_]*\s*\(|reset_[A-Za-z0-9_]*\s*\(|"
    r"mark_(claimed|consumed|redeemed|processed)\s*\(|"
    r"set_(claimed|consumed|redeemed|processed)\s*\(|"
    r"(claimed|consumed|redeemed|processed)[A-Za-z0-9_]*\s*=\s*true)"
)

_STOP_TOKENS = {
    "address",
    "amount",
    "claim",
    "contract",
    "env",
    "event",
    "false",
    "get",
    "i128",
    "mut",
    "self",
    "set",
    "storage",
    "token",
    "transfer",
    "true",
    "u128",
    "u32",
    "user",
}


def _norm(token: str) -> str:
    out = re.sub(r"[^a-z0-9]+", "", token.lower())
    if out.endswith("ies") and len(out) > 4:
        out = out[:-3] + "y"
    elif out.endswith("s") and len(out) > 5:
        out = out[:-1]
    return out


def _accounting_tokens(body_text: str) -> set[str]:
    tokens: set[str] = set()
    for raw in _STRING_TOKEN_RE.findall(body_text):
        if _ACCOUNTING_WORD_RE.search(raw):
            token = _norm(raw)
            if token and token not in _STOP_TOKENS:
                tokens.add(token)
    for raw in _DATAKEY_RE.findall(body_text):
        if _ACCOUNTING_WORD_RE.search(raw):
            token = _norm(raw)
            if token and token not in _STOP_TOKENS:
                tokens.add(token)
    for match in _IDENT_TOKEN_RE.finditer(body_text):
        token = _norm(match.group(0))
        if token and token not in _STOP_TOKENS:
            tokens.add(token)
    return tokens


def _is_credit_path(name: str, body_text: str, tokens: set[str]) -> bool:
    return (
        bool(tokens)
        and bool(_CREDIT_NAME_RE.search(name))
        and bool(_STORAGE_WRITE_RE.search(body_text))
        and bool(_ARITH_CREDIT_RE.search(body_text))
    )


def _is_spend_path(name: str, body_text: str, tokens: set[str]) -> bool:
    return (
        bool(tokens)
        and bool(_SPEND_NAME_RE.search(name))
        and bool(_VALUE_MOVE_RE.search(body_text))
    )


def _first_match(pattern: re.Pattern[str], text: str) -> int | None:
    match = pattern.search(text)
    if match is None:
        return None
    return match.start()


def run(tree, source: bytes, filepath: str):
    hits = []
    by_impl: dict[int, list[dict[str, object]]] = {}

    for fn, impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        name = fn_name(fn, source)
        tokens = _accounting_tokens(body_nc)
        by_impl.setdefault(id(impl), []).append(
            {
                "node": fn,
                "name": name,
                "body": body_nc,
                "tokens": tokens,
                "is_credit": _is_credit_path(name, body_nc, tokens),
                "is_spend": _is_spend_path(name, body_nc, tokens),
            }
        )

    for fns in by_impl.values():
        credits = [fn for fn in fns if fn["is_credit"]]
        spends = [fn for fn in fns if fn["is_spend"]]
        if not credits or not spends:
            continue

        for spend in spends:
            spend_tokens = spend["tokens"]
            matched_credit = None
            shared_tokens: set[str] = set()
            for credit in credits:
                shared = set(credit["tokens"]) & set(spend_tokens)
                if shared:
                    matched_credit = credit
                    shared_tokens = shared
                    break
            if matched_credit is None:
                continue

            value_pos = _first_match(_VALUE_MOVE_RE, str(spend["body"]))
            consume_pos = _first_match(_CONSUME_RE, str(spend["body"]))
            if consume_pos is not None and (
                value_pos is None or consume_pos < value_pos
            ):
                continue

            node = spend["node"]
            line, col = line_col(node)
            issue = "never clears or decrements"
            if consume_pos is not None and value_pos is not None and consume_pos > value_pos:
                issue = "clears or decrements only after value movement"
            hits.append(
                {
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(node, source, 180),
                    "message": (
                        f"pub fn `{spend['name']}` {issue} accounting state "
                        f"{sorted(shared_tokens)} credited by "
                        f"`{matched_credit['name']}` before moving value. "
                        f"Paired accounting paths need consume/decrement/clear "
                        f"before payout to prevent repeat claim or fund loss "
                        f"(arithmetic-state-write-asymmetry-fire10)."
                    ),
                }
            )

    return hits
