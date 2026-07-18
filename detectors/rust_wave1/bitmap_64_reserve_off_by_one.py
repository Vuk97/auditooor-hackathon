"""
bitmap_64_reserve_off_by_one.py

Flags 64-reserve-bitmap off-by-one / unbounded-index bugs. K2's
UserConfiguration is a 128-bit bitmap (2 bits per reserve, max 64 reserves).
If an index isn't `< 64`-guarded before a shift like `(idx * 2)` or
`(idx * 2 + 1)`, out-of-range values corrupt neighboring reserve flags.

Indicators (any one is a hit):
  1. A function whose body contains a shift `(<expr> * 2)` / `(<expr> * 2 + 1)`
     or a call to `set_using_as_collateral`/`set_borrowing`/
     `is_using_as_collateral`/`is_borrowing` where the index expression is a
     fn parameter or storage read and the fn body has NO guard
     `< 64` / `<= 63` / `>= 64` on that identifier.
  2. A loop `for i in 0..N` where `N` is the literal `128` or `>= 65`, when
     `i` is used inside a shift like `(i * 2)` or `<< (i * 2)`.

Caveats:
  * Flags per-function: one guard anywhere in the fn body silences the hit for
    that identifier.
  * Shifts inside test fixtures or modules flagged `#[cfg(test)]` are skipped.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_BITMAP_METHODS = {
    "set_using_as_collateral", "set_borrowing",
    "is_using_as_collateral", "is_borrowing",
}

# `<ident> * 2` or `<ident> * 2 + 1` — shift exponents for 2-bit-per-reserve bitmaps.
_SHIFT_EXPO_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\*\s*2\b"
)


def _fn_params(fn_node, source: bytes) -> set:
    names = set()
    for c in fn_node.children:
        if c.type == "parameters":
            for p in c.children:
                if p.type != "parameter":
                    continue
                # pattern: identifier/mutable_specifier then `:` then type
                for pc in p.children:
                    if pc.type == "identifier":
                        names.add(text_of(pc, source))
                        break
    return names


def _has_bound_guard(body_text: str, ident: str) -> bool:
    """True if the function body contains an early-return/panic guard on
    `ident` against 64 or 63 (any relational direction)."""
    patterns = [
        rf"\b{re.escape(ident)}\s*>=\s*64\b",
        rf"\b{re.escape(ident)}\s*>\s*63\b",
        rf"\b{re.escape(ident)}\s*<\s*64\b",
        rf"\b{re.escape(ident)}\s*<=\s*63\b",
        rf"\b64\s*<=\s*{re.escape(ident)}\b",
        rf"\b63\s*<\s*{re.escape(ident)}\b",
        # panic helpers from K2
        rf"safe_reserve_id\s*\([^)]*{re.escape(ident)}",
    ]
    return any(re.search(p, body_text) for p in patterns)


def _find_loop_issues(body, source: bytes):
    """Yield call_nodes / range_nodes for `for i in 0..N` loops where
    N is suspicious (>= 65 or 128) and i is used in a *2 shift downstream."""
    out = []
    body_text = text_of(body, source)
    for n in walk_no_nested_fn(body):
        if n.type != "for_expression":
            continue
        loop_text = text_of(n, source)
        m = re.search(r"for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+0\s*\.\.=?\s*(\d+|[A-Z_][A-Z0-9_]*)", loop_text)
        if not m:
            continue
        loop_var = m.group(1)
        upper_raw = m.group(2)
        is_suspicious = False
        if upper_raw.isdigit():
            upper = int(upper_raw)
            if upper >= 65:
                is_suspicious = True
        # constant name like NUM_RESERVES -- we can't resolve; accept only if
        # also using with *2 and the name isn't obviously MAX_RESERVES (64).
        # Skip constants for now (too noisy).
        if not is_suspicious:
            continue
        if re.search(rf"\b{re.escape(loop_var)}\s*\*\s*2\b", loop_text):
            out.append(n)
    return out


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)
        params = _fn_params(fn, source)
        name = fn_name(fn, source)

        # Indicator 1a: named bitmap methods where index arg is an identifier
        # without a guard.
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            callee = None
            args = None
            for c in n.children:
                if c.type in ("field_expression",
                              "scoped_identifier", "identifier"):
                    callee = c
                    break
            for c in n.children:
                if c.type == "arguments":
                    args = c
            if callee is None or args is None:
                continue
            method = None
            if callee.type == "field_expression":
                for c in callee.children:
                    if c.type == "field_identifier":
                        method = text_of(c, source)
            if method not in _BITMAP_METHODS:
                continue
            # First positional arg
            first_arg = None
            for c in args.children:
                if c.type not in ("(", ")", ","):
                    first_arg = c
                    break
            if first_arg is None:
                continue
            idx_text = text_of(first_arg, source).strip()
            # Accept only identifiers (most risky). Bail on integer literals.
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", idx_text):
                continue
            if _has_bound_guard(body_text, idx_text):
                continue
            # Fn-param-only is strongest signal — but also flag any unguarded
            # local used here.
            line, col = line_col(n)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(n, source),
                "message": (f"fn `{name}` calls `{method}({idx_text}, ...)` "
                            f"with no `{idx_text} < 64` guard in the body — "
                            f"an OOB reserve index corrupts neighboring "
                            f"bitmap flags (K2 UserConfiguration class)."),
            })

        # Indicator 1b: shift expression `(<ident> * 2)` with ident being a
        # fn parameter and no bound guard.
        for n in walk_no_nested_fn(body):
            if n.type != "binary_expression":
                continue
            # We want `<<` or `>>` where RHS is `<ident> * 2 [+1]`.
            op = None
            for c in n.children:
                if c.type in ("<<", ">>"):
                    op = c.type
                    break
            if op is None:
                continue
            rhs_text = text_of(n, source).split(op, 1)[1]
            for m in _SHIFT_EXPO_RE.finditer(rhs_text):
                ident = m.group(1)
                if ident not in params:
                    continue
                if _has_bound_guard(body_text, ident):
                    continue
                line, col = line_col(n)
                hits.append({
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(n, source),
                    "message": (f"fn `{name}` shifts by `{ident} * 2` where "
                                f"`{ident}` is a parameter and the body "
                                f"contains no `< 64` guard — an OOB index "
                                f"produces undefined shift behavior on a "
                                f"128-bit bitmap."),
                })
                break  # one shift per binary_expression is enough

        # Indicator 2: loop with suspicious upper bound
        for loop_node in _find_loop_issues(body, source):
            line, col = line_col(loop_node)
            hits.append({
                "severity": "med",
                "line": line,
                "col": col,
                "snippet": snippet_of(loop_node, source),
                "message": (f"fn `{name}` loops `0..N` with N >= 65 and uses "
                            f"`i * 2` as a shift exponent — exceeds the "
                            f"64-reserve / 128-bit bitmap layout."),
            })

    return hits
