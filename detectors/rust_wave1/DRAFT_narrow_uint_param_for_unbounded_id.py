"""
DRAFT_narrow_uint_param_for_unbounded_id.py

# DRAFT: auto-generated sibling for narrow-uint-param-for-unbounded-id (source side: solidity).
# Review required before enabling. Do NOT add to test_detectors.sh yet.

BUG_CLASS: narrow-uint-param-for-unbounded-id
description: Public function declares narrow uint8/uint16 parameter for a token/NFT id while the contract mints against an unbounded counter — once the id passes the param's max (256 / 65536) the ABI truncates and those holders are permanently locked out of the function (Solodit #32188 AI Arena FighterFarm::reRoll)

Auto-translated from: reference/patterns.dsl/narrow-uint-param-for-unbounded-id.yaml

This is a REVIEWER PROMPT — translation is best-effort from the Solidity
DSL regex/precondition shape into a tree-sitter-rust heuristic. Human must:
  1. Confirm the bug-class actually manifests on the Rust side (Soroban /
     Solana / Move / Sway / FunC / TON / CosmWasm). If not, delete this file
     and leave the class `solidity_only`.
  2. Replace the naive regex scan below with AST-level predicates matching
     the actual Rust shape of the bug (see e.g. delegatecall_to_user_address.py
     which ports EVM delegatecall → Soroban SEP-41 transfer-from spoof).
  3. Add fixtures: test_fixtures/DRAFT_narrow_uint_param_for_unbounded_id_positive.rs
     and _negative.rs, then register in test_detectors.sh.
"""
from __future__ import annotations

import re

from _util import (
    fn_name,
    functions_in_contractimpl,
    is_pub,
    line_col,
    snippet_of,
    source_nocomment,
    text_of,
)


_NARROW_ID_PARAM_RE = re.compile(
    r"\b(?:token_id|nft_id|item_id|fighter_id|card_id|id)\s*:\s*u(?:8|16)\b"
)
_ID_FN_RE = re.compile(
    r"(?i)(reroll|re_roll|claim|withdraw|burn|upgrade|equip|use_item|token_uri|metadata|settle|redeem)"
)
_UNBOUNDED_COUNTER_RE = re.compile(
    r"(?is)"
    r"(?:(?:next|token|nft|fighter|card|item)_?id\s*:\s*(?:u32|u64|u128|usize))|"
    r"(?:(?:\w+\.)?(?:next|token|nft|fighter|card|item)_?id\s*(?:\+=\s*1|=\s*(?:\w+\.)?(?:next|token|nft|fighter|card|item)_?id\s*\+\s*1))|"
    r"(?:(?:\w+\.)?(?:next|token|nft|fighter|card|item)_?id\s*=\s*(?:\w+\.)?(?:next|token|nft|fighter|card|item)_?id\s*\.checked_add\s*\(\s*1\s*\))"
)
_MINT_RE = re.compile(r"(?i)\b(mint|safe_mint|create_\w*token|create_\w*nft|spawn_\w*fighter)\s*\(")


def run(tree, source: bytes, filepath: str):
    hits = []
    module_nc = source_nocomment(source)
    if not (_UNBOUNDED_COUNTER_RE.search(module_nc) and _MINT_RE.search(module_nc)):
        return hits

    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        fn_text = text_of(fn, source)
        if not _NARROW_ID_PARAM_RE.search(fn_text):
            continue
        if not _ID_FN_RE.search(name):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source),
            "message": (
                f"pub fn `{name}` accepts a u8/u16 token-style id while the "
                "contract also mints from an unbounded wider id counter. "
                "Once minted ids exceed the narrow range, holders can be "
                "locked out of this entrypoint."
            ),
        })
    return hits


# --- Source-side excerpt (reference only) ------------------------------------
# # Auto-migrated by tools/dsl-migration-helper.py 2026-04-19 | pattern: narrow-uint-param-for-unbounded-id | source: solodit-32188-ai-arena-fighter-farm-reroll | severity: HIGH | confidence: MEDIUM | tier: B | preconditions: |   - contract.source_matches_regex: '(ERC721|ERC1155|NFT|Token|Fighter|Card|Item)' | match:
