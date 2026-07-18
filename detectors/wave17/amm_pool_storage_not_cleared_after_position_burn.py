"""
amm-pool-storage-not-cleared-after-position-burn — generated from reference/patterns.dsl/amm-pool-storage-not-cleared-after-position-burn.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py amm-pool-storage-not-cleared-after-position-burn.yaml
Source: defimon-deep-mine/Yieldification_YDF_2026-01-26_post-2552 ($1.3K + writeup)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AmmPoolStorageNotClearedAfterPositionBurn(AbstractDetector):
    ARGUMENT = "amm-pool-storage-not-cleared-after-position-burn"
    HELP = "AMM remove-position path burns the position NFT without deleting `pools[tokenId]`. The zombie pool record retains reserve metadata; later `swapPool(tokenId, …)` against the burned id transfers real tokens out, draining funds another user pre-deposited."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/amm-pool-storage-not-cleared-after-position-burn.yaml"
    WIKI_TITLE = "AMM pool storage persists after position-NFT burn — zombie pool drainable via burned tokenId"
    WIKI_DESCRIPTION = "DEX-style contracts that mint an ERC721 representing each pool/position must DELETE the per-tokenId storage struct (`pools[tokenId]`, `positions[tokenId]`) inside the same transaction that burns the tokenId. When `poolRemove(tokenId)` calls `_burn(tokenId)` but leaves the storage struct alive, downstream functions (`swapPool`, `harvest`, `claim`) that key off the same tokenId still see non-zero re"
    WIKI_EXPLOIT_SCENARIO = "Yieldification YDF, BSC, 2026-01-26 (post-2552, $1.3K — small loss but textbook shape). Token: $YDF. Type: 'Logic Error - Storage Not Cleared After NFT Burn'. The protocol's pool struct `pools[tokenId]` persisted after `poolRemove()` burned the NFT. Attacker created a pool, removed it (burn fired, storage stayed), then called `swapPool(burnedTokenId, …)` reading the stale pool reserves and drainin"
    WIKI_RECOMMENDATION = "Always pair `_burn(tokenId)` with `delete pools[tokenId]` (or the equivalent `delete positions[tokenId]`, `delete pairs[tokenId]`) in the same function body. Add an `_existsPool(tokenId)` modifier on every interaction function that reads pool storage — it should revert if `_ownerOf(tokenId) == addre"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(pool|position|pair).*\\bstruct\\b|swapPool|removeLiquidity|poolRemove|burn\\s*\\(\\s*tokenId|_burn\\s*\\(\\s*tokenId|\\bERC721\\b'}, {'contract.has_state_var_matching': '(pools|positions|pairs|poolInfo|positionInfo)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(poolRemove|removeLiquidity|removePool|burnPosition|removePosition|closePosition|exitPool)$'}, {'function.body_contains_regex': '(_burn|burn)\\s*\\(\\s*(tokenId|positionId|poolId|nftId)\\s*\\)|_burn\\s*\\(\\s*\\w+\\s*,\\s*(tokenId|positionId|poolId|nftId)\\s*\\)'}, {'function.body_not_contains_regex': 'delete\\s+(pools|positions|pairs|poolInfo|positionInfo)\\s*\\[|_clearPool\\s*\\(|_clearPosition\\s*\\(|(pools|positions|pairs|poolInfo|positionInfo)\\s*\\[\\s*\\w+\\s*\\]\\s*=\\s*\\w+\\s*\\(\\s*0|(pools|positions|pairs)\\s*\\[\\s*\\w+\\s*\\]\\.\\w+\\s*=\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" — amm-pool-storage-not-cleared-after-position-burn: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
