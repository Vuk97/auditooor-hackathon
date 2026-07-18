"""
liquidation_seize_collateral_wrong_user.py

Flags liquidation / seize functions where collateral is transferred FROM
the wrong account — classic `transfer_from(liquidator, ...)` bug when the
code should be pulling from the `borrower` / `user`.

Heuristic:
  1. Function name contains `liquidat` or `seize`.
  2. Function parameter list contains at least TWO of: `user`, `borrower`,
     `liquidator`, `on_behalf_of`, `collateral_owner`.
  3. Body calls `.transfer_from(X, ...)` or `.transfer(X, ...)` where X is
     `liquidator` / `caller` AND the transfer semantics require pulling
     from the borrower.

Specifically we flag when:
  - `.transfer_from(liquidator` appears (transfer-from normally pulls; here
    it pulls from the liquidator — wrong party).
  - `.transfer(from: liquidator`, `...)` where destination is NOT the
    liquidator (transferring OUT of the liquidator but into protocol —
    actually this is normally the repay leg, so we skip unless ALSO a
    collateral identifier is in the same expression).

Conservative: we require a `collateral` / `ctoken` token reference in the
same 120-char window around the call to avoid flagging the debt-repay
transfer leg.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_LIQ_RE = re.compile(r"(liquidat|seize|_seize_)", re.IGNORECASE)

_WRONG_ACTORS = ("liquidator", "caller", "msg_sender")
_RIGHT_ACTORS = ("borrower", "user", "on_behalf_of", "collateral_owner",
                 "debtor")

_COLLATERAL_HINTS = ("collateral", "ctoken", "c_token", "a_token",
                      "atoken", "share", "kinetic_token")


def _param_names(fn_node, source: bytes) -> set[str]:
    names = set()
    for c in fn_node.children:
        if c.type == "parameters":
            for p in c.children:
                if p.type == "parameter":
                    for pc in p.children:
                        if pc.type == "identifier":
                            names.add(text_of(pc, source))
                            break
    return names


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not _LIQ_RE.search(name):
            continue
        params = _param_names(fn, source)
        # Need both a liquidator AND a borrower-ish parameter to be suspicious
        has_wrong = any(a in params for a in _WRONG_ACTORS)
        has_right = any(a in params for a in _RIGHT_ACTORS)
        if not (has_wrong and has_right):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            t = text_of(n, source)
            # Only care about transfer_from / transfer
            if ".transfer_from(" not in t and ".transfer(" not in t:
                continue
            # Find the method name + use tree-sitter's arguments node
            method = None
            args_node = None
            for c in n.children:
                if c.type == "field_expression":
                    for cc in c.children:
                        if cc.type == "field_identifier":
                            method = text_of(cc, source)
                if c.type == "arguments":
                    args_node = c
            if method not in ("transfer", "transfer_from"):
                continue
            if args_node is None:
                continue
            # Split top-level args by commas (respect nesting)
            arg_list = []
            depth = 0
            cur = ""
            raw = text_of(args_node, source).strip()
            if raw.startswith("("):
                raw = raw[1:]
            if raw.endswith(")"):
                raw = raw[:-1]
            for ch in raw:
                if ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    depth -= 1
                if ch == "," and depth == 0:
                    arg_list.append(cur.strip().lstrip("&"))
                    cur = ""
                else:
                    cur += ch
            if cur.strip():
                arg_list.append(cur.strip().lstrip("&"))
            # Soroban `.transfer(from, to, amount)` — arg[0] is source
            # Soroban `.transfer_from(spender, from, to, amount)` — arg[1]
            if method == "transfer_from":
                if len(arg_list) < 2:
                    continue
                source_arg = arg_list[1]
            else:
                if len(arg_list) < 1:
                    continue
                source_arg = arg_list[0]
            source_token = source_arg.split(".")[0].split("(")[-1].strip()
            if source_token not in _WRONG_ACTORS:
                continue
            # Must look like a COLLATERAL transfer (not debt repay)
            window_start = max(0, n.start_byte - 120)
            window_end = min(len(source), n.end_byte + 120)
            window = source[window_start:window_end].decode(
                "utf-8", errors="replace").lower()
            if not any(h in window for h in _COLLATERAL_HINTS):
                continue

            line, col = line_col(n)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(n, source),
                "message": (
                    f"fn `{name}` calls `.{method}` with "
                    f"`{source_token}` as source — collateral should be "
                    f"seized FROM the borrower, not the liquidator."
                ),
            })
    return hits
