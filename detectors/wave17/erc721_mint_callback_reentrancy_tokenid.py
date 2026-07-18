"""
erc721-mint-callback-reentrancy-tokenid — generated from reference/patterns.dsl/erc721-mint-callback-reentrancy-tokenid.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc721-mint-callback-reentrancy-tokenid.yaml
Source: auditooor/cross-cluster-nft
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc721MintCallbackReentrancyTokenid(AbstractDetector):
    ARGUMENT = "erc721-mint-callback-reentrancy-tokenid"
    HELP = "_safeMint triggers onERC721Received which re-enters a DIFFERENT mutating function on the same contract before the first mint's state writes complete."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc721-mint-callback-reentrancy-tokenid.yaml"
    WIKI_TITLE = "ERC721 safeMint callback enables cross-function tokenId reentrancy"
    WIKI_DESCRIPTION = "`_safeMint` invokes `onERC721Received` on the recipient. If the recipient is an attacker contract, the callback can re-enter any other external mutating function on the minter (e.g., a staking deposit, a claim, a second mint path) while the original mint's post-call state writes are still pending. Unlike the direct duplicate-tokenId pattern, this variant exploits cross-function state that depends "
    WIKI_EXPLOIT_SCENARIO = "A platform offers `mintAndStake`: `_safeMint(to, id); stake(id);`. Post-mint bookkeeping (e.g., `nextId += 1; hasMinted[to] = true`) happens after `_safeMint`. Attacker's recipient contract receives `onERC721Received` and re-enters the same contract's `deposit(id)` for a different user flow, or calls `claimReward()` which reads the still-stale bookkeeping. Because no `nonReentrant` guard exists, t"
    WIKI_RECOMMENDATION = "Apply `nonReentrant` on every external/public function that invokes `_safeMint` or `safeMint`. Ensure all state writes (ID counter, per-wallet caps, stake registration) happen BEFORE the `_safeMint` call (CEI). Use a single contract-wide ReentrancyGuard so cross-function reentry is blocked, not just"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'mint|_mint|safeMint|_safeMint'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '_safeMint|safeMint'}, {'function.body_ordered_regex': {'first': '_safeMint|safeMint', 'second': '(?i)(nextId|tokenId|minted|stakedBy|stakeCount|hasMinted|supply|balance|ownerOf|_owners)\\w*(?:\\s*\\[|\\s*(?:=|\\+=|\\+\\+|--))'}}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock'], 'negate': True}}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc721-mint-callback-reentrancy-tokenid: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
