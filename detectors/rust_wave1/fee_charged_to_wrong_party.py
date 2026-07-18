"""
fee_charged_to_wrong_party.py

Flags fns where a protocol fee variable is subtracted/added against a party
that does not match the convention (e.g. fee deducted from `recipient`
instead of `sender`, or fee paid from `treasury` subtracted from `caller`).

Heuristic:
  1. fn body declares a local named `fee`, `protocol_fee`, `platform_fee`,
     or `treasury_fee` (assigned from arithmetic).
  2. Same body contains a token transfer `client.transfer(A, B, amount)` where
     the `amount` literally equals `fee` or `total - fee`.
  3. The `from` arg of that transfer (A) is a parameter named `recipient`,
     `to`, `receiver`, `beneficiary`, `out`, or `dst` — which indicates the
     fee is being deducted from the wrong side.

Because tree-sitter visibility is limited, we do a focused text check on
transfer arguments.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_FEE_TOKENS = (
    "fee", "protocol_fee", "platform_fee", "treasury_fee",
    "flash_fee", "flash_loan_premium",
)

_WRONG_FROM_PARAMS = (
    "recipient", "receiver", "beneficiary", "to", "out", "dst",
    "target",
)


def _transfer_calls(body, source):
    for n in walk_no_nested_fn(body):
        if n.type != "call_expression":
            continue
        t = text_of(n, source)
        if re.search(r"\.transfer\s*\(", t):
            yield n, t


def _first_arg_from_transfer(call_text: str) -> str | None:
    """Extract first argument inside outermost (...) of a `.transfer(...)`."""
    m = re.search(r"\.transfer\s*\((.*)\)", call_text, re.DOTALL)
    if not m:
        return None
    inner = m.group(1)
    # naive split on top-level commas
    depth = 0
    args = []
    buf = []
    for ch in inner:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        args.append("".join(buf).strip())
    if not args:
        return None
    first = args[0].lstrip("&").strip()
    # strip `.clone()` and similar
    first = re.sub(r"\.clone\(\)\s*$", "", first)
    return first


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        # must have a fee-flavored local
        if not any(re.search(r"\blet\s+" + t + r"\b", body_text)
                   for t in _FEE_TOKENS):
            continue

        name = fn_name(fn, source)
        for call, ctext in _transfer_calls(body, source):
            # does the call reference a fee token?
            if not any(t in ctext for t in _FEE_TOKENS):
                continue
            first = _first_arg_from_transfer(ctext)
            if first is None:
                continue
            if first in _WRONG_FROM_PARAMS:
                line, col = line_col(call)
                hits.append({
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(call, source),
                    "message": (
                        f"fn `{name}` transfers a fee amount FROM "
                        f"`{first}` — looks like the protocol fee is being "
                        f"deducted from the recipient side instead of the "
                        f"payer."
                    ),
                })
    return hits
