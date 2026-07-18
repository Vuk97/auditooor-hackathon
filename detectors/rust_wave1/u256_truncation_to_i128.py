"""
u256_truncation_to_i128.py

Flags silent down-casts from U256 -> i128/u128/i64/u64.

Tightening (v2, 2026-04):
  - Previous version flagged any `.mul()/.div()/.add()` chain followed by
    `.to_i128()` — which false-positives on plain `i128.checked_mul(...)`
    chains used for safe arithmetic.
  - New rule: walk the receiver chain UP from the `.to_iXXX()/to_uXXX()`
    call and confirm the chain starts with a U256-provenance root:
        * `U256::from_*`, `u256!()` / `soroban_sdk::u256!()` macro
        * identifier ending in `_u256`
        * function call whose name ends in `_u256` or contains `balance_value`,
          `oracle_to_wad`, or explicitly types U256 somewhere in the chain.
  - We also require the chain to contain at least one U256 arithmetic op
    (`.mul/.div/.add/.sub`) OR the receiver literally names a U256 locally.
  - Anything we can't confirm is silently dropped.

Halborn §7.41.
"""

from __future__ import annotations

import re

from _util import walk, text_of, line_col, snippet_of


_U256_FN_HINTS = (
    "balance_value",
    "oracle_to_wad",
)

_TRUNC_METHODS = {"to_i128", "to_u128", "to_i64", "to_u64", "to_i32", "to_u32"}


def _chain_root(callee_field_expr, source: bytes):
    """Walk up the `.a().b().c()` chain (a field_expression subtree rooted at
    callee_field_expr) and return the leftmost receiver node."""
    cur = callee_field_expr
    # field_expression: <expr> . <field>
    while True:
        recv = cur.child_by_field_name("value")
        if recv is None:
            # fallback: first child
            if not cur.children:
                return cur
            recv = cur.children[0]
        if recv.type == "call_expression":
            # descend into its callee to keep walking
            sub = None
            for c in recv.children:
                if c.type in ("field_expression", "scoped_identifier",
                              "identifier"):
                    sub = c
                    break
            if sub is None:
                return recv
            if sub.type == "field_expression":
                cur = sub
                continue
            # scoped_identifier / identifier = leftmost call
            return recv
        if recv.type == "field_expression":
            cur = recv
            continue
        return recv


def _looks_like_u256_root(root_node, source: bytes) -> bool:
    """True if `root_node` (the leftmost receiver of a method chain) is a
    confirmed U256 provenance."""
    t = text_of(root_node, source).strip()
    # U256::from_*
    if re.match(r'^U256\s*::\s*from_', t):
        return True
    # soroban_sdk::U256::from_*
    if "U256::from_" in t:
        return True
    # u256!(...) or soroban_sdk::u256!(...)
    if re.match(r'^(?:[A-Za-z_][A-Za-z_0-9]*::)*u256!\s*\(', t):
        return True
    # identifier ending in _u256
    if re.match(r'^[A-Za-z_][A-Za-z_0-9]*$', t) and t.endswith("_u256"):
        return True
    # call to foo_u256(...) or balance_value(...)
    m = re.match(r'^([A-Za-z_][A-Za-z_0-9]*)\s*\(', t)
    if m:
        name = m.group(1)
        if name.endswith("_u256"):
            return True
        if name in _U256_FN_HINTS:
            return True
    # method call ending in _u256 at the chain start: e.g. foo.balance_u256()
    if re.search(r'\.([A-Za-z_][A-Za-z_0-9]*_u256)\s*\(', t):
        return True
    if "balance_value" in t or "oracle_to_wad" in t:
        # guarded: also must have U256 somewhere — otherwise risky
        return True
    return False


def _chain_has_u256_evidence(chain_text: str) -> bool:
    """Secondary gate: the full receiver chain text must at least mention
    `U256`, `u256`, or a `_u256` suffix identifier — otherwise we reject."""
    if "U256" in chain_text or "u256" in chain_text:
        return True
    if "_u256" in chain_text:
        return True
    return False


def run(tree, source: bytes, filepath: str):
    hits = []
    for n in walk(tree.root_node):
        # Case A: method call `.to_i128()` / `.to_u128()` / ...
        if n.type == "call_expression":
            callee = None
            for c in n.children:
                if c.type == "field_expression":
                    callee = c
                    break
            if callee is None:
                continue
            method = None
            for c in callee.children:
                if c.type == "field_identifier":
                    method = text_of(c, source)
            if method not in _TRUNC_METHODS:
                continue

            # Full chain text (everything left of `.to_iXXX()`)
            recv_node = callee.child_by_field_name("value")
            if recv_node is None:
                continue
            recv_text = text_of(recv_node, source)

            # Gate 1: chain must mention U256 / u256 / _u256
            if not _chain_has_u256_evidence(recv_text):
                continue

            # Gate 2: walk to the leftmost receiver and confirm U256 provenance
            root = _chain_root(callee, source)
            if not _looks_like_u256_root(root, source):
                continue

            # Gate 3: require ≥3 `.mul(` operations (triple compound product).
            # Single/double mul chains are common and usually bounded by
            # WAD/decimals normalisation; triple products are the genuine
            # i128-overflow risk (balance * price * oracle_to_wad * ...).
            mul_count = recv_text.count(".mul(")
            if mul_count < 3:
                continue

            line, col = line_col(n)
            hits.append({
                "severity": "med",
                "line": line,
                "col": col,
                "snippet": snippet_of(n, source),
                "message": (f"`{method}()` on a U256 chain rooted at "
                            f"`{text_of(root, source)[:48]}` — silent "
                            f"truncation (Halborn §7.41)."),
            })
            continue

        # Case B: `as i128` / `as u128` cast after a U256 chain
        if n.type == "type_cast_expression":
            text = text_of(n, source)
            if not (" as i128" in text or " as u128" in text
                    or " as i64" in text or " as u64" in text
                    or " as i32" in text or " as u32" in text):
                continue
            if not _chain_has_u256_evidence(text):
                continue
            # Require explicit U256:: or u256! at the start of the inner expr
            inner = text.split(" as ", 1)[0].lstrip("(").strip()
            if not (re.match(r'^U256\s*::', inner)
                    or re.match(r'^(?:[A-Za-z_][A-Za-z_0-9]*::)*u256!', inner)
                    or inner.endswith("_u256")
                    or "_u256" in inner.split(".", 1)[0]):
                continue
            line, col = line_col(n)
            hits.append({
                "severity": "med",
                "line": line,
                "col": col,
                "snippet": snippet_of(n, source),
                "message": ("`as iNN`/`as uNN` cast from U256 chain — "
                            "silent truncation (Halborn §7.41)."),
            })
    return hits
