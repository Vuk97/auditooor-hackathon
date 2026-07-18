"""
rust_mempool_anchor_nullifier_check_absent_block_path.py

Flags a consensus-validation path asymmetry where an anchor and nullifier
validity check is gated inside an `if let Some(unmined_tx) = req.mempool_transaction()`
block (or equivalent `is_mempool()` / `mempool_transaction()` predicate), causing
it to run ONLY for mempool transactions but NOT for block transactions in the same
transaction-verifier `call()` body.

Concretely: match a call to a state service with a request variant matching
`CheckBestChainTipNullifiersAndAnchors` or `CheckNullifiersAndAnchors` that is
reachable only via a `mempool_transaction()` / `is_mempool()` predicate, AND verify
that no equivalent anchor/nullifier state query appears on the non-mempool code path
of the same function.

Real zebra occurrence:
  zebra-consensus/src/transaction.rs
  Verifier::call (Service<Request> impl, lines 521-537)
  The CheckBestChainTipNullifiersAndAnchors request is inside
  `if let Some(unmined_tx) = req.mempool_transaction() { ... }`
  with no corresponding anchor/nullifier check for the block path.

Severity: HIGH
Bug class: consensus-validation-path-asymmetry
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
# Strip string literals before scanning for identifier patterns - avoids
# false matches on error message strings that contain the variant name.
# ---------------------------------------------------------------------------
_STRING_LITERAL_RE = re.compile(r'"(?:[^"\\]|\\.)*"')


def _strip_string_literals(text: str) -> str:
    return _STRING_LITERAL_RE.sub('""', text)


# ---------------------------------------------------------------------------
# Signal 1 - function must use a mempool predicate guard
# (mempool_transaction() or is_mempool()) somewhere in the body
# ---------------------------------------------------------------------------
_MEMPOOL_GUARD_RE = re.compile(
    r"\b(?:mempool_transaction|is_mempool)\s*\(",
)

# ---------------------------------------------------------------------------
# Signal 2 - anchor/nullifier state service call that must appear INSIDE the
# mempool guard block (i.e. in the body we look for its presence alongside
# the guard, and its ABSENCE on the block path).
# ---------------------------------------------------------------------------
_ANCHOR_NULLIFIER_CALL_RE = re.compile(
    r"(?:CheckBestChainTipNullifiersAndAnchors|CheckNullifiersAndAnchors)",
)

# ---------------------------------------------------------------------------
# Signal 3 - the function also handles a block path variant.
# We look for the pattern `Request::Block` or `req.block_time()` or
# `.block_time` / `is_block()` usage, or a match arm on Block variant.
# This confirms the function handles both request types.
# ---------------------------------------------------------------------------
_BLOCK_PATH_RE = re.compile(
    r"(?:"
    r"Request\s*::\s*Block"       # match arm or constructor
    r"|req\.block_time"           # block-specific accessor
    r"|req\.is_block\s*\("        # is_block() predicate
    r"|Response\s*::\s*Block"     # block response variant
    r")",
)

# ---------------------------------------------------------------------------
# Guard: if the anchor/nullifier check appears OUTSIDE of a mempool guard
# (i.e., unconditionally in the body, OR on the block path), the pattern is
# NOT present. We heuristically detect this by checking whether the
# anchor/nullifier call occurs in the body WITHOUT the mempool guard in
# close proximity (within 200 chars before it). If both mempool-gated and
# non-mempool-gated calls exist, the asymmetry is addressed.
# ---------------------------------------------------------------------------

def _mempool_gated_nullifier_present(body_text: str) -> bool:
    """Return True if CheckBestChainTipNullifiersAndAnchors / CheckNullifiersAndAnchors
    appears inside a mempool_transaction() / is_mempool() gated block.
    Heuristic: the anchor/nullifier call occurs after a mempool guard in the text.
    Operates on string-literal-stripped text to avoid false matches in assert messages."""
    stripped = _strip_string_literals(body_text)
    anchor_matches = list(_ANCHOR_NULLIFIER_CALL_RE.finditer(stripped))
    if not anchor_matches:
        return False
    guard_matches = list(_MEMPOOL_GUARD_RE.finditer(stripped))
    if not guard_matches:
        return False
    # For each anchor/nullifier match, check if any guard appears within
    # 600 chars before it (accounts for the if-let block opening + closure chain).
    for am in anchor_matches:
        for gm in guard_matches:
            if 0 <= am.start() - gm.start() <= 600:
                return True
    return False


def _unconditional_nullifier_check_present(body_text: str) -> bool:
    """Return True if there is an anchor/nullifier check that appears to be
    unconditional (NOT preceded by a mempool guard within 600 chars).
    Operates on string-literal-stripped text to avoid false matches."""
    stripped = _strip_string_literals(body_text)
    anchor_matches = list(_ANCHOR_NULLIFIER_CALL_RE.finditer(stripped))
    guard_matches = list(_MEMPOOL_GUARD_RE.finditer(stripped))

    for am in anchor_matches:
        # Check if any mempool guard appears within 600 chars before this call
        guarded = any(
            0 <= am.start() - gm.start() <= 600
            for gm in guard_matches
        )
        if not guarded:
            # This anchor/nullifier call is not mempool-gated -> asymmetry fixed
            return True
    return False


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Must reference a mempool predicate guard
        if not _MEMPOOL_GUARD_RE.search(body_text):
            continue

        # Must reference an anchor/nullifier state service call
        if not _ANCHOR_NULLIFIER_CALL_RE.search(body_text):
            continue

        # Must also handle a block path (dual-path function)
        if not _BLOCK_PATH_RE.search(body_text):
            continue

        # The anchor/nullifier check must be inside a mempool-gated block
        if not _mempool_gated_nullifier_present(body_text):
            continue

        # If an unconditional (non-mempool-gated) anchor/nullifier check also
        # exists, the asymmetry is addressed - skip.
        if _unconditional_nullifier_check_present(body_text):
            continue

        name = fn_name(fn, source)

        # Find the best hit location: the anchor/nullifier call node
        hit_node = body
        for node in walk_no_nested_fn(body):
            if node.type in ("call_expression", "identifier", "field_identifier"):
                t = text_of(node, source)
                if _ANCHOR_NULLIFIER_CALL_RE.search(t):
                    hit_node = node
                    break

        line, col = line_col(hit_node)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(hit_node, source),
            "message": (
                f"fn `{name}`: anchor and nullifier validity check "
                "(CheckBestChainTipNullifiersAndAnchors / CheckNullifiersAndAnchors) "
                "is gated inside a `mempool_transaction()` / `is_mempool()` guard block "
                "and is absent for the block-transaction code path. "
                "Any regression or ordering bug in the state-side check leaves a window "
                "where a block containing a double-nullifier or stale-anchor spend is "
                "accepted at the tx-verifier level, causing a potential chain split. "
                "Add an equivalent anchor/nullifier state check on the block path, or "
                "refactor to a single unconditional check for both paths."
            ),
        })

    return hits
