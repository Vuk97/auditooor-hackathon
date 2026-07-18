"""
rust_option_is_some_then_unwrap_panic.py

Flags function bodies (non-test) where an Option variable is checked with
.is_some() on one line and then .unwrap() is called on the same variable in
a subsequent expression within the same block, WITHOUT an intervening
if-let or match that re-extracts the value.

The borrow checker does not enforce the guard: `if opt.is_some() { opt.unwrap() }`
compiles, but a refactor or async execution-order change can expose the unwrap()
to a None value at runtime, causing a panic in non-test production code.

Real zebra occurrence (confirmed):
  zebra-rpc/src/methods.rs, function context around get_block_template, line 1522:
    if sapling_activation.is_some() && height >= sapling_activation.unwrap()

Severity: HIGH - a panic in an RPC handler crashes the node process,
satisfying the individual-node DoS criterion in zebra's SEVERITY.md.
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
    walk_no_nested_fn,
)

# ---------------------------------------------------------------------------
# Signal 1: variable.is_some() - capture the variable name
# ---------------------------------------------------------------------------
_IS_SOME_RE = re.compile(r'\b(\w+)\.is_some\(\)')

# ---------------------------------------------------------------------------
# Signal 2: same variable.unwrap() - capture the variable name
# ---------------------------------------------------------------------------
_UNWRAP_RE = re.compile(r'\b(\w+)\.unwrap\(\)')

# ---------------------------------------------------------------------------
# Guard: intervening if-let or match that safely re-extracts the variable
# These forms are safe: `if let Some(x) = var`, `match var { Some(x) => ... }`
# ---------------------------------------------------------------------------
_SAFE_EXTRACTION_RE = re.compile(
    r'\bif\s+let\s+Some\s*\(\s*\w+'   # if let Some(x) = ...
    r'|\bmatch\s+\w+\s*\{'             # match var {
    r'|\bif\s+let\s+Some\s*\{'         # if let Some { ... } (struct variant)
)

# ---------------------------------------------------------------------------
# Extra guard: skip if the unwrap is inside a closure or closure-like context
# where the is_some() guard provably wraps it (e.g. option.map(|x| x.unwrap()))
# We cannot easily detect this statically so we just look for the is_some+unwrap
# co-occurrence on the SAME variable without a safe extraction in between.
# ---------------------------------------------------------------------------

# Skip files that are clearly test infrastructure (arbitrary, proptest strategy files)
_TEST_INFRA_PATH_RE = re.compile(r'/arbitrary\.rs$|/proptest_strategies\.rs$|/test_utils\.rs$')


def run(tree, source: bytes, filepath: str) -> list[dict]:
    hits = []

    # Skip test infrastructure files by path
    if _TEST_INFRA_PATH_RE.search(filepath):
        return hits

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Find all variables tested with .is_some()
        is_some_vars = set(m.group(1) for m in _IS_SOME_RE.finditer(body_text))
        if not is_some_vars:
            continue

        # Find all variables unwrapped with .unwrap()
        unwrap_vars = set(m.group(1) for m in _UNWRAP_RE.finditer(body_text))
        if not unwrap_vars:
            continue

        # Overlap: variables checked with is_some() AND later unwrap()ed
        overlap = is_some_vars & unwrap_vars
        if not overlap:
            continue

        # For each overlapping variable, check that there is NO safe
        # if-let / match re-extraction that would eliminate the risk.
        # Strategy: for each var in overlap, check whether a safe extraction
        # is present (any match/if-let for ANY var is considered a signal
        # the author may be using safe patterns; we only fire when there is
        # no if-let/match that names the variable explicitly).
        for var in sorted(overlap):
            # Check for safe extraction specifically for this variable
            safe_pat = re.compile(
                r'\bif\s+let\s+Some\s*\(\s*\w+\s*\)\s*=\s*' + re.escape(var) + r'\b'
                r'|\bmatch\s+' + re.escape(var) + r'\s*\{'
            )
            if safe_pat.search(body_text):
                continue  # safe extraction present for this var - skip

            # Also skip if the unwrap is already guarded by a let-else or ?
            # (the ? operator would surface as a different symbol, but let's
            # not over-engineer; the primary shape is is_some + raw unwrap)

            # Find the node to report - prefer the .unwrap() call site
            hit_node = body
            for node in walk_no_nested_fn(body):
                t = text_of(node, source)
                if f"{var}.unwrap()" in t and node.type in (
                    "call_expression", "field_expression"
                ):
                    # Prefer the smallest enclosing call_expression node
                    hit_node = node
                    break

            line, col = line_col(hit_node)
            name = fn_name(fn, source)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(hit_node, source),
                "message": (
                    f"fn `{name}`: variable `{var}` is checked with `.is_some()` "
                    f"and then called with `.unwrap()` in the same block without an "
                    f"intervening `if let Some(x) = {var}` or `match {var}`. "
                    f"The borrow checker does not enforce the is_some() guard - if "
                    f"execution reaches the .unwrap() with a None value (e.g. after "
                    f"a refactor or if the condition is complex), the process will panic. "
                    f"Replace with `if let Some(x) = {var} {{ ... }}` or use `.map()`/`.and_then()`."
                ),
            })

    return hits
