"""
r94_unchecked_approve_return.py

Flags calls to `approve(...)` / `increase_allowance(...)` /
`decrease_allowance(...)` whose `Result<(), _>` return value is silently
dropped via:
  - `let _ = token.approve(...)`   (explicit throwaway)
  - expression-statement with trailing `;` and NO `?` / `unwrap()` /
    `expect(...)` / `.ok()` / `.err()` / `.is_ok()` / `.is_err()`
    / `match`

Background: Solodit #64933 (Garden, Code4rena). For non-standard
ERC-20-style token programs on Soroban / Solana / other Rust chains,
`approve` returns `Result<(), ProgramError>`; USDT-style tokens can
return `Ok(())` for silent failure OR return a non-panicking error
that signals the allowance wasn't actually written. Dropping the
Result means downstream `transfer_from` reverts at use time,
permanently locking funds.

Maps to Solidity:
  - r94-reverse-flashloan-premium-rounded-down (no direct)
  - glider-unchecked-approve-return-value  <-- Solidity sibling if present

Heuristic:
  1. Walk every `call_expression` in every fn body.
  2. If callee is `.approve(`, `.increase_allowance(`, `.decrease_allowance(`
     (field-method access — we don't match free-function names):
       a. Check whether the call is the RHS of a binding (`let _ = ...`
          or `let _x = ...`) without `?` / method chain.
       b. OR the call is an expression-statement (parent is
          `expression_statement`) without `?` / method chain tail.
  3. Chain-tail that makes it SAFE (skip):
     `?`, `.unwrap()`, `.expect(...)`, `.is_ok()`, `.is_err()`,
     `.ok()`, `.err()`, `.unwrap_or(...)`, `.unwrap_or_else(...)`,
     `.map_err(...)`, `.map(...)`, trailing `match ... { ... }`,
     assignment to a bound variable that is later checked.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    walk_no_nested_fn, text_of, line_col, snippet_of,
    direct_method_name,
)


_APPROVE_METHODS = ("approve", "increase_allowance", "decrease_allowance")

# Tail markers that prove the caller is handling the Result
_HANDLED_TAIL_RE = re.compile(
    r"(\?\s*[;,)]|"                              # postfix ?
    r"\.unwrap\s*\(|"                             # .unwrap()
    r"\.expect\s*\(|"                             # .expect(...)
    r"\.is_ok\s*\(|\.is_err\s*\(|"                # .is_ok() / .is_err()
    r"\.ok\s*\(|\.err\s*\(|"                      # .ok() / .err()
    r"\.unwrap_or\s*\(|\.unwrap_or_else\s*\(|"    # .unwrap_or*
    r"\.map\s*\(|\.map_err\s*\(|"                 # .map / .map_err
    r"\.and_then\s*\(|\.or_else\s*\()",           # .and_then / .or_else
)


def _parent_type(node):
    return node.parent.type if node.parent else None


def _gp_type(node):
    return node.parent.parent.type if node.parent and node.parent.parent else None


def _call_is_unchecked(call_node, source: bytes) -> bool:
    """True if this call_expression's Result is silently dropped."""
    call_text = text_of(call_node, source)

    # Check surrounding (via next ~60 chars in source) for a handled-tail marker
    end = call_node.end_byte
    tail = source[end:end + 80].decode("utf8", errors="replace")
    if _HANDLED_TAIL_RE.search(tail):
        return False

    # Also check for tail markers immediately adjacent, e.g. `foo.approve(...)?`
    # The tail check above covers `?;`, `?,`, `?)`.

    parent = call_node.parent
    if parent is None:
        return False
    ptype = parent.type

    # Expression statement with no binding, no chain, just `foo.approve(...);`
    if ptype == "expression_statement":
        return True

    # Let-binding to _: `let _ = foo.approve(...);`
    if ptype == "let_declaration":
        pat = None
        for c in parent.children:
            if c.type == "identifier" or c.type.endswith("pattern"):
                pat = c
                break
        if pat is not None and text_of(pat, source).strip() == "_":
            return True
        # Let-binding to a named variable that is never re-read is ALSO
        # a potential concern, but too high-FP for a heuristic — skip.

    return False


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        body = fn_body(fn)
        if body is None:
            continue
        name = fn_name(fn, source)

        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            # Match only the direct method on THIS call_expression
            method = direct_method_name(n, source)
            if method not in _APPROVE_METHODS:
                continue
            if not _call_is_unchecked(n, source):
                continue
            line, col = line_col(n)
            hits.append({
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snippet_of(n, source),
                "message": (
                    f"fn `{name}` calls `.approve(...)` / `.increase_allowance(...)` / "
                    f"`.decrease_allowance(...)` and drops the Result "
                    f"(no `?`, `.unwrap()`, `.expect(...)`, `.is_ok()`, etc). "
                    f"Non-standard token programs can silently fail the "
                    f"allowance write — subsequent `transfer_from` will revert, "
                    f"locking funds. See Solodit #64933 (Garden)."
                ),
            })
    return hits
