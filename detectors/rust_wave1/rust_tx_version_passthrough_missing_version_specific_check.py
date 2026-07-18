"""
rust_tx_version_passthrough_missing_version_specific_check.py

Flags a transaction-version-specific verification function that is
implemented as a pure passthrough to a previous version's function, with
no additional version-specific consensus checks.

Target shape:

  1. The function name matches `verify_v<N>_transaction` (regex) where N
     is a decimal version number.

  2. The function carries a #[cfg(...)] attribute referencing a network-
     upgrade feature (zcash_unstable, nu7, tx_v<N>, or similar upgrade
     feature flag) in a preceding attribute_item.

  3. The function body consists of exactly ONE non-trivial expression
     statement: a delegating call to `Self::verify_v<M>_transaction(...)`
     where M < N (or at least M != N, to generalise).

  4. The body has NO additional `check::`, `validate_`, or `verify_`
     calls (no extra consensus checks around the delegation).

Rationale:
  A new transaction version introduced by a network upgrade (e.g. V6 /
  NU7) that silently reuses a prior version's verification function
  inherits neither new consensus rules for that version nor any version-
  specific network-upgrade gate.  If the new version adds mandatory
  fields or new constraints absent from the old version, the passthrough
  causes invalid new-version transactions to be accepted.

Real zebra occurrence:
  zebra-consensus/src/transaction.rs  Verifier::verify_v6_transaction
  lines 981-988 (tagged #[cfg(all(zcash_unstable = "nu7", feature =
  "tx_v6"))], body = single call to Self::verify_v5_transaction).
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
# Signal 1 - function name must be verify_v<N>_transaction
# ---------------------------------------------------------------------------
_FN_NAME_RE = re.compile(r"^verify_v(\d+)_transaction$")

# ---------------------------------------------------------------------------
# Signal 2 - a preceding attribute_item must reference a network-upgrade
# feature flag.  We look for the raw text of the fn node's preceding
# attribute siblings for upgrade-feature keywords.
# ---------------------------------------------------------------------------
_UPGRADE_ATTR_RE = re.compile(
    r"""
    zcash_unstable               # Zcash unstable feature gate
    | nu\d                       # nu7, nu8, ... upgrade identifiers
    | tx_v\d                     # tx_v6, tx_v7, ...
    | network_upgrade            # generic upgrade feature name
    | feature\s*=\s*"[^"]*v\d   # feature = "anything_vN"
    """,
    re.VERBOSE | re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Signal 3 - the body delegates to Self::verify_v<M>_transaction(...)
# ---------------------------------------------------------------------------
_DELEGATE_RE = re.compile(r"Self\s*::\s*verify_v(\d+)_transaction\s*\(")

# ---------------------------------------------------------------------------
# Signal 4 - absence of additional verification calls
#
# If the body contains any of these patterns BESIDES the delegation call,
# the author did add version-specific checks; skip.
# ---------------------------------------------------------------------------
_EXTRA_CHECK_RE = re.compile(
    r"""
    \bcheck\s*::              # check::something(
    | \bvalidate_\w           # validate_foo(
    | \bverify_v\d            # verify_vN (any version - catches multi-calls)
    | verify_\w+_transaction  # another verify_X_transaction helper
    | verify_\w+_bundle       # verify_sapling_bundle, verify_orchard_bundle, etc.
    | verify_\w+_inputs       # verify_transparent_inputs_and_outputs, etc.
    """,
    re.VERBOSE | re.IGNORECASE,
)


_TEST_ATTR_RE = re.compile(r"#\s*\[\s*(?:test|cfg\s*\(\s*test|tokio\s*::\s*test)", re.IGNORECASE)


def _is_test_fn(fn_node, source: bytes) -> bool:
    """Return True only if the function is annotated with a genuine test
    attribute: #[test], #[cfg(test)], or #[tokio::test].
    Unlike the _util.in_test_cfg helper which treats ANY #[cfg(...)] as
    test code, this check is precise."""
    prev = fn_node.prev_named_sibling
    while prev is not None and prev.type in (
        "attribute_item", "line_comment", "block_comment"
    ):
        if prev.type == "attribute_item":
            attr_text = text_of(prev, source)
            if _TEST_ATTR_RE.search(attr_text):
                return True
        prev = prev.prev_named_sibling
    # Also check enclosing mod #[cfg(test)]
    n = fn_node.parent
    while n is not None:
        if n.type == "mod_item":
            p = n.prev_named_sibling
            while p is not None and p.type in ("attribute_item", "line_comment", "block_comment"):
                if p.type == "attribute_item":
                    t = text_of(p, source)
                    if "cfg(test)" in t or ("cfg" in t and "test" in t):
                        return True
                p = p.prev_named_sibling
        n = n.parent
    return False


def _fn_has_upgrade_attr(fn_node, source: bytes) -> bool:
    """Return True if a preceding attribute_item references a network-upgrade
    feature flag.  We skip over doc-comment nodes (line_comment / block_comment)
    when looking for attributes, since Rust doc comments sit between the
    attribute and the function item in the tree-sitter AST."""
    prev = fn_node.prev_named_sibling
    while prev is not None and prev.type in (
        "attribute_item", "line_comment", "block_comment"
    ):
        if prev.type == "attribute_item":
            attr_text = text_of(prev, source)
            if _UPGRADE_ATTR_RE.search(attr_text):
                return True
        prev = prev.prev_named_sibling
    return False


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if _is_test_fn(fn, source):
            continue

        # Signal 1: name must be verify_v<N>_transaction
        name = fn_name(fn, source)
        m = _FN_NAME_RE.match(name)
        if not m:
            continue
        version_n = int(m.group(1))

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Signal 3: body must contain exactly one delegation to
        # Self::verify_v<M>_transaction
        delegate_matches = list(_DELEGATE_RE.finditer(body_text))
        if len(delegate_matches) != 1:
            continue

        # Confirm the delegatee version is numerically lower (the common
        # case) or at least a different version.
        version_m = int(delegate_matches[0].group(1))
        if version_m >= version_n:
            continue  # calling a newer/same version - different pattern

        # Signal 4: no additional check / validate / verify calls
        # Strip the delegation call itself before searching for extras
        body_no_delegate = _DELEGATE_RE.sub("", body_text)
        if _EXTRA_CHECK_RE.search(body_no_delegate):
            continue

        # Signal 2: function must have an upgrade-feature attribute
        if not _fn_has_upgrade_attr(fn, source):
            continue

        # Report at the opening of the function body
        line, col = line_col(body)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(body, source),
            "message": (
                f"`{name}` (V{version_n}) is a pure passthrough to "
                f"`Self::verify_v{version_m}_transaction` with no "
                f"V{version_n}-specific consensus checks. "
                f"If the network upgrade that introduces V{version_n} "
                f"mandates new validation rules not present in V{version_m}, "
                f"invalid V{version_n} transactions will be accepted, "
                f"diverging from validators that correctly implement those rules. "
                f"Add at minimum a V{version_n} network-upgrade gate check "
                f"(analogous to verify_v{version_m}_transaction_network_upgrade) "
                f"or inline the required new consensus checks."
            ),
        })

    return hits
