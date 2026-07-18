"""
missing_slippage_in_swap_call.py

Flags call-sites of swap-like functions whose argument list does not contain a
slippage / minimum-output parameter, OR where a min-output parameter is
hardcoded to `0` / `i128::MIN`.

Maps to wave4/5 slippage class.

Heuristic:
  - Call-expression whose method name (last field_identifier) matches a
    swap-ish pattern: `swap`, `swap_exact_in`, `swap_exact_out`, `exact_input`,
    `exact_output`, `path_swap`, or anything containing `swap` or `exchange`.
  - Extract the argument list text and check for the presence of a
    `min_amount_out` / `min_swap_output` / `min_out` / `min_return` /
    `slippage` identifier or a named literal of that shape.
  - Flag if no such arg is present, OR if it is present but passed as
    literal `0` / `0i128` / `i128::MIN`.
"""

from __future__ import annotations

import re

from _util import walk, text_of, line_col, snippet_of


_SWAP_RE = re.compile(
    r'^(swap|swap_exact_in|swap_exact_out|swap_exact_tokens|'
    r'swap_exact_tokens_direct|swap_exact_tokens_for_tokens|'
    r'swap_tokens_for_exact_tokens|swap_via_handler|exact_input|'
    r'exact_output|path_swap|exchange|exchange_exact_in)$'
)
# Conservative: only allow function names that actually START with swap_ or
# exchange_ and are NOT getters/setters/validators/queries.
_LOOSE_SWAP_RE = re.compile(
    r'^(swap_|exchange_)', re.IGNORECASE
)
# Reject list — names that include swap/exchange but are admin plumbing.
_REJECT_PREFIXES = (
    "get_", "set_", "is_", "validate_", "check_", "read_", "load_",
    "store_", "update_",
)
_REJECT_CONTAINS = (
    "whitelist", "handler_whitelist", "config", "_bps", "health_factor",
    "_output", "reserve", "factory", "pair", "quote",
)

_MIN_OUT_RE = re.compile(
    r'\b(min_amount_out|min_out|min_return|min_swap_output|'
    r'minimum_out|min_received|slippage)\b'
)

_ZERO_LITERAL_RE = re.compile(
    r'^\s*(0|0i128|0_i128|0u128|0_u128|i128::MIN)\s*$'
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for n in walk(tree.root_node):
        if n.type != "call_expression":
            continue
        # Extract callee method name
        callee = None
        for c in n.children:
            if c.type == "field_expression":
                callee = c
                break
        method = None
        if callee is not None:
            for c in callee.children:
                if c.type == "field_identifier":
                    method = text_of(c, source)
        else:
            # Could be direct `swap(...)` call — check first identifier
            for c in n.children:
                if c.type in ("identifier", "scoped_identifier"):
                    t = text_of(c, source)
                    # take last ident after ::
                    method = t.split("::")[-1]
                    break
        if method is None:
            continue

        # Fast reject: getters / setters / validators / queries — these
        # carry "swap" in the name as namespace, not as action.
        lname = method.lower()
        if any(lname.startswith(p) for p in _REJECT_PREFIXES):
            continue
        if any(bad in lname for bad in _REJECT_CONTAINS):
            continue
        # Also reject wrapper RPC names like `call_soroswap` — the outer call
        # carries the opcode as a string arg; it isn't a direct swap call-site.
        if lname.startswith("call_"):
            continue

        # Match either strict list or starts-with-swap_/exchange_
        if not (_SWAP_RE.match(method) or _LOOSE_SWAP_RE.match(method)):
            continue

        # Extract argument list text
        args_node = None
        for c in n.children:
            if c.type == "arguments":
                args_node = c
                break
        if args_node is None:
            continue
        args_text = text_of(args_node, source)

        # Drop if args text contains a "min*" kwarg OR a comment reference
        m = _MIN_OUT_RE.search(args_text)
        if m:
            # Is the value literal 0 / i128::MIN?
            # Grab the surrounding context — from the matched name up to next
            # balanced comma or close paren.
            start = m.end()
            tail = args_text[start:]
            # Strip leading `:` / `=` / `,` / whitespace
            val_match = re.match(r'\s*[:=,]?\s*([^,\)]+)', tail)
            if val_match and _ZERO_LITERAL_RE.match(val_match.group(1)):
                line, col = line_col(n)
                hits.append({
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(n, source),
                    "message": (f"`{method}(...)` passes `{m.group(1)}` = "
                                f"zero/MIN — effectively unbounded slippage."),
                })
            continue

        # No min-out argument found at all
        line, col = line_col(n)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(n, source),
            "message": (f"`{method}(...)` called without any "
                        f"`min_amount_out` / `slippage` argument — caller "
                        f"is exposed to full slippage / sandwich."),
        })
    return hits
