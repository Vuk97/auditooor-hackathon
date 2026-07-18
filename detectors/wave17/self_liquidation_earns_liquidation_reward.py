"""
self-liquidation-earns-liquidation-reward — generated from reference/patterns.dsl/self-liquidation-earns-liquidation-reward.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py self-liquidation-earns-liquidation-reward.yaml
Source: auditooor-R75-c4-lending-dyad-1268
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SelfLiquidationEarnsLiquidationReward(AbstractDetector):
    ARGUMENT = "self-liquidation-earns-liquidation-reward"
    HELP = "liquidate() has no same-owner check. Borrower can liquidate themselves (to a second wallet/NFT) and capture the bounty. With reflexive collateral (Kerosine-style TVL pricing) also enables self-liquidation as a price-pump."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/self-liquidation-earns-liquidation-reward.yaml"
    WIKI_TITLE = "Self-liquidation captures the liquidation reward and manipulates TVL-priced collateral"
    WIKI_DESCRIPTION = "A safety bonus paid to the liquidator (LIQUIDATION_REWARD) is meant to incentivize third parties to keep the system solvent. If `liquidate(id, to)` accepts any `to`, a borrower whose position is underwater calls it with a second NFT they own as `to`, effectively paying the bonus to themselves and turning a loss event into a neutral one. Worse: protocols where collateral is priced by an endogenous "
    WIKI_EXPLOIT_SCENARIO = "Alice has an NFT with $1000 WETH collateral and $800 debt, CR = 125% (below liq threshold 150%). Alice mints a second NFT. Instead of waiting for a third-party liquidator (who would take the 10% = $80 bonus), Alice calls `liquidate(nft1, nft2)`. The collateral + bonus moves from nft1 to nft2, all controlled by Alice. She retains the $80 that would otherwise have gone to a liquidator. If the vault "
    WIKI_RECOMMENDATION = "Add `require(ownerOf(id) != msg.sender && ownerOf(id) != ownerOf(to), \"SelfLiquidation\");` at the start of liquidate(). Alternatively, ensure the liquidation bonus is only claimable after an external keeper signals the liquidation (e.g. two-step commit-reveal) or requires proof of a price drop rat"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)liquidate\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(liquidate|_?liquidatePosition|liquidateVault)$'}, {'function.body_contains_regex': '(?i)(LIQUIDATION_REWARD|liquidationBonus|liquidationIncentive|_liquidationReward)'}, {'function.body_not_contains_regex': '(?i)(ownerOf\\s*\\(\\s*id\\s*\\)\\s*!=\\s*msg\\.sender|ownerOf\\s*\\(\\s*id\\s*\\)\\s*!=\\s*ownerOf\\s*\\(\\s*to\\s*\\)|borrower\\s*!=\\s*msg\\.sender|onBehalfOf\\s*!=\\s*msg\\.sender|require\\s*\\(\\s*msg\\.sender\\s*!=\\s*ownerOf)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — self-liquidation-earns-liquidation-reward: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
