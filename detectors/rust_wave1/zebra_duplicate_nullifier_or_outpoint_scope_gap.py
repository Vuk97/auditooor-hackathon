"""
zebra_duplicate_nullifier_or_outpoint_scope_gap.py

Flags Rust consensus validation functions that check duplicate nullifiers
or transparent outpoint spends against only one chain scope.

Zebra-fit invariant:
  - shielded nullifier duplicate checks need finalized state plus the
    non-finalized chain scope.
  - transparent outpoint spend checks need finalized UTXO lookup plus
    pending chain scope, including non-finalized spent or unspent UTXOs
    and same-block duplicate spends where applicable.

The detector is intentionally conservative. It ignores comments, skips
explicit scope-maintenance helpers, and only reports validation-like
functions that perform real duplicate-scope operations in code.
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
)


_VALIDATION_NAME_RE = re.compile(
    r"(?i)(validate|validity|check|verify|reject|accept|duplicate|"
    r"no_duplicates|transparent_spend|spend_chain_order|tx_no_duplicates)"
)

_SCOPE_SPECIFIC_HELPER_NAME_RE = re.compile(
    r"(?i)(finalized_chain|non_finalized_chain|add_to_non_finalized|"
    r"remove_from_non_finalized|update_chain_tip|revert_chain_with)"
)

_NULLIFIER_OP_RE = re.compile(
    r"(?x)"
    r"(?:"
    r"\b(?:sprout|sapling|orchard)_nullifiers\s*\(|"
    r"\.\s*(?:sprout|sapling|orchard)_nullifiers\b|"
    r"\bcontains_(?:sprout|sapling|orchard)_nullifier\s*\(|"
    r"\bduplicate_nullifier_error\s*\(|"
    r"\bDuplicateNullifier"
    r")"
)

_OUTPOINT_OP_RE = re.compile(
    r"(?x)"
    r"(?:"
    r"\btransparent::OutPoint\b|"
    r"\bOutPoint\b|"
    r"\.\s*outpoint\s*\(|"
    r"\btransparent::Input::outpoint\b|"
    r"\b\w*spent_utxos\b|"
    r"\b\w*unspent_utxos\b|"
    r"\bblock_spends\b|"
    r"\bblock_new_outputs\b|"
    r"\bDuplicateTransparentSpend\b|"
    r"\bMissingTransparentOutput\b|"
    r"\.\s*utxo\s*\("
    r")"
)

_DUPLICATE_INTENT_RE = re.compile(
    r"(?i)(duplicate|double[_ -]?spend|already[_ -]?spent|contains_key|"
    r"contains_(?:sprout|sapling|orchard)_nullifier|insert\s*\(|"
    r"DuplicateTransparentSpend|duplicate_nullifier_error)"
)

_FINALIZED_NULLIFIER_RE = re.compile(
    r"(?x)"
    r"(?:"
    r"\bfinalized_(?:state|chain)\b|"
    r"\bZebraDb\b|"
    r"\bcontains_(?:sprout|sapling|orchard)_nullifier\s*\(|"
    r"\bfinalized_chain_contains\s*\("
    r")"
)

_PENDING_NULLIFIER_RE = re.compile(
    r"(?x)"
    r"(?:"
    r"\bnon_finalized_(?:state|chain|contains)\b|"
    r"\bnon_finalized_chain_contains\b|"
    r"\b(?:parent|best|new)_chain\b|"
    r"\.\s*(?:sprout|sapling|orchard)_nullifiers\s*\.\s*contains_key\s*\(|"
    r"\bchain_nullifiers\s*\.\s*insert\s*\(|"
    r"\badd_to_non_finalized_chain_unique\s*\("
    r")"
)

_FINALIZED_OUTPOINT_RE = re.compile(
    r"(?x)"
    r"(?:"
    r"\bfinalized_(?:state|chain)\b|"
    r"\bZebraDb\b|"
    r"\.\s*utxo\s*\("
    r")"
)

_PENDING_OUTPOINT_RE = re.compile(
    r"(?x)"
    r"(?:"
    r"\bnon_finalized_(?:state|chain)\b|"
    r"\b(?:parent|best|new)_chain\b|"
    r"\b\w*spent_utxos\s*\.\s*contains_key\s*\(|"
    r"\b\w*unspent_utxos\s*\.\s*get\s*\(|"
    r"\bblock_spends\s*\.\s*insert\s*\(|"
    r"\bblock_new_outputs\s*\.\s*get\s*\("
    r")"
)


def _domain(body: str) -> str | None:
    has_nullifier = bool(_NULLIFIER_OP_RE.search(body))
    has_outpoint = bool(_OUTPOINT_OP_RE.search(body))
    if has_nullifier and not has_outpoint:
        return "nullifier"
    if has_outpoint and not has_nullifier:
        return "outpoint"
    if has_nullifier and has_outpoint:
        return "nullifier/outpoint"
    return None


def _is_validation_candidate(name: str, body: str) -> bool:
    if _SCOPE_SPECIFIC_HELPER_NAME_RE.search(name):
        return False
    if not _VALIDATION_NAME_RE.search(name):
        return False
    return bool(_DUPLICATE_INTENT_RE.search(body))


def _scope_bits(domain: str, body: str) -> tuple[bool, bool]:
    if domain == "nullifier":
        return (
            bool(_FINALIZED_NULLIFIER_RE.search(body)),
            bool(_PENDING_NULLIFIER_RE.search(body)),
        )
    if domain == "outpoint":
        return (
            bool(_FINALIZED_OUTPOINT_RE.search(body)),
            bool(_PENDING_OUTPOINT_RE.search(body)),
        )

    finalized = bool(
        _FINALIZED_NULLIFIER_RE.search(body) or _FINALIZED_OUTPOINT_RE.search(body)
    )
    pending = bool(
        _PENDING_NULLIFIER_RE.search(body) or _PENDING_OUTPOINT_RE.search(body)
    )
    return finalized, pending


def _missing_scope(finalized: bool, pending: bool) -> str | None:
    if finalized and not pending:
        return "pending non-finalized scope"
    if pending and not finalized:
        return "finalized state scope"
    return None


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        body_nc = body_text_nocomment(body, source)
        domain = _domain(body_nc)
        if domain is None:
            continue
        if not _is_validation_candidate(name, body_nc):
            continue

        finalized, pending = _scope_bits(domain, body_nc)
        missing = _missing_scope(finalized, pending)
        if missing is None:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"fn `{name}` performs {domain} duplicate-scope "
                    f"validation but only covers one chain scope. Missing "
                    f"{missing}. Zebra-style consensus checks should bind "
                    "duplicate nullifiers and transparent spends across "
                    "both finalized state and the pending non-finalized chain."
                ),
            }
        )

    return hits
