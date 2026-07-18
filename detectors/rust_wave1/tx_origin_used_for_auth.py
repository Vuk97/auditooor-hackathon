"""
tx_origin_used_for_auth.py

Soroban analog of Solidity `tx.origin` mis-use:
  Function has multiple `Address` parameters, calls `.require_auth()` on
  one of them (call it A), then uses a DIFFERENT Address parameter (B) as
  the `from` argument in a token transfer — i.e. user B's funds are moved
  while only A authorized.

Heuristic:
  1. fn has at least 2 Address parameters.
  2. body calls `<A>.require_auth()` on exactly ONE of them.
  3. body calls `.transfer(<B>, ...)` where B is a different Address param.

We treat `B == env.current_contract_address()` and `B == A` as safe.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name, is_pub, text_of,
    walk_no_nested_fn, line_col, snippet_of,
)


def _addr_params(fn, source: bytes) -> list[str]:
    names = []
    for c in fn.children:
        if c.type != "parameters":
            continue
        for p in c.children:
            if p.type != "parameter":
                continue
            ptext = text_of(p, source)
            if "Address" not in ptext:
                continue
            for pp in p.children:
                if pp.type == "identifier":
                    names.append(text_of(pp, source))
                    break
    return names


def _first_arg(call_text: str) -> str | None:
    m = re.search(r"\.transfer\s*\((.*)\)", call_text, re.DOTALL)
    if not m:
        return None
    inner = m.group(1)
    depth = 0
    buf = []
    for ch in inner:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            break
        buf.append(ch)
    arg = "".join(buf).strip().lstrip("&")
    arg = re.sub(r"\.clone\(\)\s*$", "", arg).strip()
    return arg


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        addr_ps = _addr_params(fn, source)
        if len(addr_ps) < 2:
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        # exactly one require_auth on a param
        auths = [a for a in addr_ps
                 if re.search(r"\b" + a + r"\.require_auth\s*\(",
                              body_text)]
        if len(auths) != 1:
            continue
        auth_addr = auths[0]

        # find transfer calls
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            t = text_of(n, source)
            if ".transfer(" not in t and ".transfer_from(" not in t:
                continue
            first = _first_arg(t)
            if first is None:
                continue
            if first == auth_addr:
                continue
            # treat contract self as safe
            if "current_contract_address" in first:
                continue
            if first not in addr_ps:
                continue
            # different Address param is being used as payer
            line, col = line_col(n)
            hits.append({
                "severity": "med",
                "line": line,
                "col": col,
                "snippet": snippet_of(n, source),
                "message": (
                    f"pub fn `{fn_name(fn, source)}` calls "
                    f"`{auth_addr}.require_auth()` but transfers funds "
                    f"from a different Address param `{first}` (tx.origin-"
                    f"analog: wrong party authorized)."
                ),
            })
    return hits
