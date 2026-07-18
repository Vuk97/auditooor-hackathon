"""
rust_coinbase_maturity_mempool_only_guard.py

Flags a function (or async block inside a function) that guards a coinbase-
maturity or coinbase-spend-restriction check behind an `is_mempool()` (or
analogous boolean-test-on-context-variant) predicate, such that the same
check is absent for the sibling path (block / finalized path).

Concretely, this fires when ALL of the following hold:

  1. There exists an `if_expression` whose condition is a call to a method
     matching `is_mempool`, `is_block`, `is_proposal`, `is_finalized`, or
     any single-variant predicate on a request/context enum (matched as
     `<receiver>.is_<variant>()`).

  2. The consequent block of that `if_expression` calls a function whose
     name contains `maturity`, `coinbase_spend`, or `transparent_coinbase`
     (i.e. one of the coinbase-maturity check family).

  3. There is NO `else_clause` on that same `if_expression`.

  4. The SAME check-family function name does NOT appear anywhere else in
     the enclosing async block / function body OUTSIDE the guarded `if`
     block.  (This rules out cases where the developer repeats the check
     unconditionally on the other path.)

  5. The containing scope is NOT a test-cfg function.

Verified real surface:
  zebra-consensus/src/transaction.rs  Verifier::call  (lines 477-479)

    if req.is_mempool() {
        Self::check_maturity_height(&network, &req, &spent_utxos)?;
    }
    // No else branch and no unconditional check_maturity_height call;
    // the block-inclusion path silently skips coinbase-maturity validation.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    line_col,
    snippet_of,
    text_of,
    walk,
    walk_no_nested_fn,
    IDENT,
)

# ---------------------------------------------------------------------------
# Pattern 1: method name looks like a single-variant predicate on a
# request / context object: <anything>.is_mempool(), .is_block(), etc.
# ---------------------------------------------------------------------------
_IS_VARIANT_RE = re.compile(
    r"\b\w+\s*\.\s*is_(?:mempool|block|proposal|finalized|accepted|rejected)\s*\(\s*\)"
)

# ---------------------------------------------------------------------------
# Pattern 2: function calls that belong to the coinbase-maturity check family
# ---------------------------------------------------------------------------
_MATURITY_CHECK_NAMES = re.compile(
    r"\b(?:check_maturity_height|coinbase_maturity|coinbase_spend"
    r"|transparent_coinbase_spend|tx_transparent_coinbase_spends_maturity)\b"
)


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _walk_async_blocks(fn_node):
    """Yield every async_block node that is a direct descendant of fn_node
    (not nested inside another function)."""
    body = fn_body(fn_node)
    if body is None:
        return
    for node in walk_no_nested_fn(body):
        if node.type == "async_block":
            yield node


def _call_name_in_node(node, source: bytes) -> str | None:
    """If node is a call_expression, return the callee identifier name."""
    if node.type != "call_expression":
        return None
    if not node.children:
        return None
    callee = node.children[0]
    # Direct identifier: foo()
    if callee.type == "identifier":
        return text_of(callee, source)
    # Scoped: Self::check_maturity_height(...) or crate::foo::bar(...)
    if callee.type == "scoped_identifier":
        for c in reversed(callee.children):
            if c.type == "identifier":
                return text_of(c, source)
    # Field: obj.method(...)
    if callee.type == "field_expression":
        for c in callee.children:
            if c.type == "field_identifier":
                return text_of(c, source)
    return None


def _if_has_no_else(if_node) -> bool:
    return not any(c.type == "else_clause" for c in if_node.children)


def _condition_is_variant_predicate(if_node, source: bytes) -> bool:
    """True if the `if` condition is a single-variant predicate like
    `req.is_mempool()` or `req.is_block()`."""
    # The condition is child index 1 (after the `if` keyword token)
    for c in if_node.children:
        if c.type in ("call_expression", "unary_expression"):
            cond_text = text_of(c, source)
            if _IS_VARIANT_RE.search(cond_text):
                return True
    return False


def _consequent_calls_maturity_check(if_node, source: bytes) -> str | None:
    """Return the first maturity-check function name found in the consequent
    block, or None."""
    for c in if_node.children:
        if c.type == "block":
            block_text = body_text_nocomment(c, source)
            m = _MATURITY_CHECK_NAMES.search(block_text)
            if m:
                return m.group(0)
    return None


def _maturity_check_appears_outside_if(scope_node, if_node, source: bytes) -> bool:
    """Return True if the maturity-check family appears OUTSIDE the given
    if_node within scope_node (i.e. an unconditional call on the other path)."""
    scope_text_full = body_text_nocomment(scope_node, source)
    # How many times does the pattern appear in the full scope?
    all_hits = list(_MATURITY_CHECK_NAMES.finditer(scope_text_full))
    if len(all_hits) <= 1:
        return False  # Only one occurrence — it must be the guarded one

    # Count occurrences inside the if-block to compare
    if_block_text = ""
    for c in if_node.children:
        if c.type == "block":
            if_block_text = body_text_nocomment(c, source)
            break
    inside_count = len(list(_MATURITY_CHECK_NAMES.finditer(if_block_text)))
    outside_count = len(all_hits) - inside_count
    return outside_count > 0


# ---------------------------------------------------------------------------
# Main run
# ---------------------------------------------------------------------------

def run(tree, source: bytes, filepath: str):
    hits = []
    # Track (fn_node_id, if_node_id) pairs to avoid double-reporting the same
    # if_expression when both the function body and an inner async_block scope
    # independently traverse it.
    seen: set[int] = set()

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        # Collect candidate scopes: the function body itself, plus any
        # async_block children (handles the `fn call() { async move { ... } }`
        # pattern common in Tower Service impls).
        candidate_scopes = []
        fn_b = fn_body(fn)
        if fn_b is not None:
            candidate_scopes.append(fn_b)
        for ab in _walk_async_blocks(fn):
            candidate_scopes.append(ab)

        for scope in candidate_scopes:
            # Walk all if_expressions inside this scope (no nested fns)
            for node in walk_no_nested_fn(scope):
                if node.type != "if_expression":
                    continue

                # Gate 1: condition is a single-variant predicate
                if not _condition_is_variant_predicate(node, source):
                    continue

                # Gate 2: no else branch
                if not _if_has_no_else(node):
                    continue

                # Gate 3: consequent block calls a maturity-check function
                check_name = _consequent_calls_maturity_check(node, source)
                if check_name is None:
                    continue

                # Gate 4: same check family does NOT appear outside the guard
                # (i.e. it is NOT called unconditionally on the other path)
                if _maturity_check_appears_outside_if(scope, node, source):
                    continue

                # Dedup: same if_expression node from multiple scope traversals
                if id(node) in seen:
                    continue
                seen.add(id(node))

                name = fn_name(fn, source)
                line, col = line_col(node)
                hits.append({
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(node, source),
                    "message": (
                        f"fn `{name}`: coinbase-maturity check (`{check_name}`) is "
                        "guarded behind an `is_mempool()` (or equivalent variant-"
                        "predicate) with no else-branch and no unconditional call "
                        "on the block-inclusion path. A transaction that arrives via "
                        "the block path bypasses the maturity check, allowing immature "
                        "coinbase outputs to be spent; nodes enforcing the rule will "
                        "reject the block, causing a consensus split."
                    ),
                })

    return hits
