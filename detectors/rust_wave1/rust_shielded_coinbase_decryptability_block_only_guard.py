"""
rust_shielded_coinbase_decryptability_block_only_guard.py

Flags a consensus-critical ZIP-212 check that is present in a block-level
verifier's `call()` body but is structurally absent from the per-transaction
verifier's `call()` body.

Concrete real-world shape (zebra-consensus):
  block.rs  SemanticBlockVerifier::call (line 259):
      tx::check::coinbase_outputs_are_decryptable(&coinbase_tx, &network, height)?;
  transaction.rs  Verifier::call (~line 391):
      -- no call to coinbase_outputs_are_decryptable anywhere in the fn body --

ZIP-212 mandates that shielded Sapling/Orchard coinbase outputs be
decryptable using the all-zero outgoing viewing key.  A node that runs the
block-level check but not the per-transaction check can fail to validate
a proposal or mempool path that bypasses block-level verification, causing
a potential chain split with nodes that enforce the rule at both layers.

Match conditions (ALL required to fire):
  1. Function name is `call` (Service::call implementation).
  2. The function body (excluding nested functions) contains a call matching
     `coinbase.*decryptable|decryptable.*coinbase` (case-insensitive), i.e.
     a call to `coinbase_outputs_are_decryptable` or a sibling helper.
  3. The same body also contains evidence it is the OUTER / block-level
     verifier: it references `transaction_verifier` (a nested verifier field)
     OR contains `tx::Request::Block` (dispatching per-transaction work).
     This condition excludes the transaction verifier's own `call()` body
     and any function that performs the check directly without delegation.
  4. Function is not test-only (no #[test] / #[cfg(test)] attribute).

Severity: HIGH
Rubric row: Non-permanent chain split - ZIP-212 mandates that shielded
Sapling/Orchard coinbase outputs be decryptable by the all-zero key.
A block accepted by a node that skips this check diverges from nodes that
enforce it.

Why it generalises:
  'Check X at layer N but not at layer N-1 when layer N-1 can be exercised
  independently' recurs in any layered consensus validator (block-verifier
  wrapping transaction-verifier).  Detectors that flag a consensus-critical
  function call present in an outer handler but absent from the inner handler
  catch this entire class on any Rust target with a comparable architecture.
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
    walk_no_nested_fn,
    text_of,
)

# ---------------------------------------------------------------------------
# Signal 1 - the function MUST be named `call`
# (matches Service::call for both block and tx verifiers)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Signal 2 - coinbase-decryptability check is present in this body
# The real name is `coinbase_outputs_are_decryptable`; we match the pattern
# broadly to catch renamed helpers in analogous layered validators.
# ---------------------------------------------------------------------------
_COINBASE_DECRYPT_RE = re.compile(
    r"coinbase.*decryptable|decryptable.*coinbase",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Signal 3 - outer / block-verifier evidence
# The body must delegate to a per-transaction verifier; this distinguishes
# the block-verifier call() from the transaction-verifier call().
# Two sufficient signals (either one satisfies):
#   a) References a `transaction_verifier` field (the delegated inner verifier)
#   b) Dispatches a `tx::Request::Block` / `Request::Block` message
# ---------------------------------------------------------------------------
_TX_VERIFIER_DELEGATION_RE = re.compile(
    r"transaction_verifier\b"
    r"|tx::Request::Block\b"
    r"|Request::Block\s*\{",
    re.IGNORECASE,
)


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        # Skip test functions
        if in_test_cfg(fn, source):
            continue

        # Must be named `call`
        name = fn_name(fn, source)
        if name != "call":
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Signal 2: coinbase-decryptability call must be present
        if not _COINBASE_DECRYPT_RE.search(body_text):
            continue

        # Signal 3: outer/block-verifier delegation evidence must be present
        if not _TX_VERIFIER_DELEGATION_RE.search(body_text):
            continue

        # Find the exact call node to point at (the coinbase decryptability call)
        hit_node = None
        for node in walk_no_nested_fn(body):
            if node.type not in ("call_expression",):
                continue
            call_text = text_of(node, source)
            if _COINBASE_DECRYPT_RE.search(call_text):
                hit_node = node
                break

        if hit_node is None:
            hit_node = body

        line, col = line_col(hit_node)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(hit_node, source),
            "message": (
                f"Block-level verifier `{name}` calls `coinbase_outputs_are_decryptable` "
                "(ZIP-212 shielded coinbase output decryptability check) but delegates "
                "transaction verification to an inner verifier that does NOT repeat this "
                "check for the `Request::Block` path. A block-proposal validation path that "
                "exercises the transaction verifier directly (bypassing this block-level "
                "`call`) will skip the ZIP-212 check, allowing a node to accept a coinbase "
                "whose shielded outputs are not decryptable with the all-zero key - "
                "diverging from fully-validating nodes and risking a chain split. "
                "Apply `coinbase_outputs_are_decryptable` inside the transaction verifier "
                "when handling `Request::Block` coinbase transactions."
            ),
        })

    return hits
