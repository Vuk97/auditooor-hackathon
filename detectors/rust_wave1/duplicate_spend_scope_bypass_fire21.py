"""
duplicate_spend_scope_bypass_fire21.py

Rust same-class recall lift for duplicate-spend-scope-bypass.

Flags validation or spend-marker code that keys duplicate-spend prevention
by a nullifier, outpoint, receipt, or spend id without the scope that makes
two spends unique across branch, asset, chain, or transaction context.

Detector hits are candidate evidence only, not exploit proof.
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
)


DETECTOR_ID = "rust_wave1.duplicate_spend_scope_bypass_fire21"

_CANDIDATE_NAME_RE = re.compile(
    r"(?i)(validate|check|ensure|reject|accept|record|mark|spend|spent|"
    r"receipt|nullifier|outpoint|duplicate|scope)"
)

_DUPLICATE_CONTEXT_RE = re.compile(
    r"(?i)\b(nullifier|outpoint|receipt|spent_utxo|spent_utxos|unspent_utxo|"
    r"unspent_utxos|spend_marker|spent_receipt|spent_receipts|spent_marker|"
    r"double_spend|already_spent|contains_key|insert\s*\()"
)

_SCOPE_TERM_RE = re.compile(
    r"(?i)\b(branch_id|branch|fork_id|fork|asset_id|asset|chain_id|chain|"
    r"tx_id|txid|transaction_id|transaction|block_hash|block_id|height|"
    r"network_id|network|context|finalized_state|non_finalized_chain)"
)

_NULLIFIER_OP_RE = re.compile(
    r"(?i)(sapling_nullifiers\s*\(|orchard_nullifiers\s*\(|"
    r"sprout_nullifiers\s*\(|contains_(?:sapling|orchard|sprout)_nullifier\s*\()"
)

_FINALIZED_NULLIFIER_RE = re.compile(
    r"(?i)(\bfinalized_(?:state|chain)\b|ZebraDb|"
    r"contains_(?:sapling|orchard|sprout)_nullifier\s*\()"
)

_PENDING_NULLIFIER_RE = re.compile(
    r"(?i)(non_finalized_(?:state|chain|contains)|parent_chain|best_chain|"
    r"new_chain|(?:sapling|orchard|sprout)_nullifiers\s*\.\s*contains_key\s*\(|"
    r"chain_nullifiers\s*\.\s*(?:contains_key|insert)\s*\()"
)

_OUTPOINT_OP_RE = re.compile(
    r"(?i)(OutPoint|spent_utxos|unspent_utxos|block_spends|"
    r"block_new_outputs|DuplicateTransparentSpend|MissingTransparentOutput|"
    r"\.utxo\s*\()"
)

_FINALIZED_OUTPOINT_RE = re.compile(
    r"(?i)(\bfinalized_(?:state|chain)\b|ZebraDb|\.utxo\s*\()"
)

_PENDING_OUTPOINT_RE = re.compile(
    r"(?i)(non_finalized_(?:state|chain)|parent_chain|best_chain|new_chain|"
    r"\w*spent_utxos\s*\.\s*contains_key\s*\(|"
    r"\w*unspent_utxos\s*\.\s*get\s*\(|"
    r"block_spends\s*\.\s*(?:contains_key|insert)\s*\(|"
    r"block_new_outputs\s*\.\s*get\s*\()"
)

_NARROW_KEY_OP_RE = re.compile(
    r"(?is)"
    r"(?P<map>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
    r"\s*\.\s*(?P<op>contains_key|insert|remove|get)\s*\(\s*&?\s*"
    r"(?P<key>nullifier|outpoint|spend|spend_id|receipt|receipt_id|"
    r"note_id|marker_id|txid|tx_id)\b"
)

_COMPOSITE_SCOPE_KEY_RE = re.compile(
    r"(?is)("
    r"let\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*\([^;]*(?:branch|fork|asset|chain|"
    r"tx_id|txid|transaction|block_hash|network)[^;]*(?:nullifier|outpoint|"
    r"spend|receipt|note_id|marker_id)[^;]*\)|"
    r"(?:struct\s+)?[A-Za-z0-9_]*Scope[A-Za-z0-9_]*\s*\{[^{}]*(?:branch|fork|"
    r"asset|chain|tx_id|txid|transaction|block_hash|network)[^{}]*"
    r"(?:nullifier|outpoint|spend|receipt|note_id|marker_id)[^{}]*\}|"
    r"(?:contains_key|insert|remove|get)\s*\(\s*&?\s*\([^)]*(?:branch|fork|"
    r"asset|chain|tx_id|txid|transaction|block_hash|network)[^)]*"
    r"(?:nullifier|outpoint|spend|receipt|note_id|marker_id)[^)]*\)"
    r")"
)

_FINALIZED_ONLY_HELPER_RE = re.compile(
    r"(?i)(^|_)(?:no_)?duplicates?_in_finalized_chain|"
    r"finalized_(?:chain|state)"
)


def _signature_text(fn, source: bytes) -> str:
    return text_of(fn, source).split("{", 1)[0]


def _missing_zebra_nullifier_scope(body: str) -> str | None:
    if not _NULLIFIER_OP_RE.search(body):
        return None

    finalized = bool(_FINALIZED_NULLIFIER_RE.search(body))
    pending = bool(_PENDING_NULLIFIER_RE.search(body))
    if finalized and not pending:
        return "nullifier duplicate check covers finalized state but not the pending non-finalized chain"
    if pending and not finalized:
        return "nullifier duplicate check covers pending chain state but not finalized state"
    return None


def _missing_zebra_outpoint_scope(body: str) -> str | None:
    if not _OUTPOINT_OP_RE.search(body):
        return None

    finalized = bool(_FINALIZED_OUTPOINT_RE.search(body))
    pending = bool(_PENDING_OUTPOINT_RE.search(body))
    if finalized and not pending:
        return "transparent spend lookup covers finalized state but not pending chain spends"
    if pending and not finalized:
        return "transparent spend lookup covers pending chain spends but not finalized state"
    return None


def _missing_composite_spend_key(signature: str, body: str) -> str | None:
    joined = f"{signature}\n{body}"
    if not _SCOPE_TERM_RE.search(joined):
        return None
    if _COMPOSITE_SCOPE_KEY_RE.search(body):
        return None

    match = _NARROW_KEY_OP_RE.search(body)
    if match is None:
        return None

    map_name = match.group("map")
    key_name = match.group("key")
    if re.search(r"(?i)utxo", map_name):
        return None
    if not re.search(r"(?i)(spent|spend|receipt|nullifier|outpoint|marker)", map_name):
        return None

    return (
        f"{map_name}.{match.group('op')} is keyed only by `{key_name}` "
        "even though branch, asset, chain, or transaction scope is available"
    )


def _build_hit(filepath: str, line: int, col: int, name: str, variant: str, detail: str, snippet: str) -> dict:
    return {
        "detector_id": DETECTOR_ID,
        "severity": "high",
        "file": filepath,
        "line": line,
        "col": col,
        "fn_name": name,
        "variant": variant,
        "snippet": snippet,
        "message": (
            f"fn `{name}` matches duplicate-spend-scope-bypass variant "
            f"`{variant}`: {detail}. Duplicate-spend prevention keys must "
            "bind the spend marker to its chain, branch, asset, or tx scope."
        ),
    }


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body_node = fn_body(fn)
        if body_node is None:
            continue

        name = fn_name(fn, source)
        signature = _signature_text(fn, source)
        body = body_text_nocomment(body_node, source)
        if _FINALIZED_ONLY_HELPER_RE.search(name) and "scope" not in name.lower():
            continue
        if not _CANDIDATE_NAME_RE.search(f"{name}\n{signature}"):
            continue
        if not _DUPLICATE_CONTEXT_RE.search(body):
            continue

        checks = [
            ("zebra-nullifier-one-scope", _missing_zebra_nullifier_scope(body)),
            ("zebra-outpoint-one-scope", _missing_zebra_outpoint_scope(body)),
            ("narrow-spend-marker-key", _missing_composite_spend_key(signature, body)),
        ]

        line, col = line_col(fn)
        snippet = snippet_of(fn, source)[:260]
        for variant, detail in checks:
            if detail is None:
                continue
            hits.append(_build_hit(filepath, line, col, name, variant, detail, snippet))

    return hits
