"""
category-supply-below-mint-cap-locks-eth — generated from reference/patterns.dsl/category-supply-below-mint-cap-locks-eth.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py category-supply-below-mint-cap-locks-eth.yaml
Source: solodit/pashov/baton-launchpad-26452
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CategorySupplyBelowMintCapLocksEth(AbstractDetector):
    ARGUMENT = "category-supply-below-mint-cap-locks-eth"
    HELP = "`initialize` takes per-category supply array AND a global maxMintSupply without asserting `sum(categories.supply) >= maxMintSupply`. If misconfigured, the mint-finished gate is unreachable and collected ETH is locked forever."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/category-supply-below-mint-cap-locks-eth.yaml"
    WIKI_TITLE = "Per-category supply sum not cross-checked against global mint cap — ETH trapped on completion gate"
    WIKI_DESCRIPTION = "A launchpad / ICO / NFT-drop contract takes a per-category supply array (each category has its own mint limit) plus a global `maxMintSupply`. The reaching-completion logic depends on the global cap (`totalMinted == maxMintSupply` triggers finalization, which releases ETH to the creator and enables refunds). The `initialize` function does not assert that `sum(categories[i].supply) >= maxMintSupply`"
    WIKI_EXPLOIT_SCENARIO = "Creator deploys `Nft.initialize(categories=[{supply:50,price:0.1}, {supply:50,price:0.2}], maxMintSupply=1000, vestingParams=..., refundParams=...)`. Total possible mints: 100. Cap: 1000. Users mint all 100 slots, pay ~15 ETH. Contract expects `totalMinted == 1000` to finalize; it will never arrive. ETH is stuck; vesting never activates (vesting.start gated on finalize); refunds are disabled (refu"
    WIKI_RECOMMENDATION = "In `initialize`, assert `sum(categories[i].supply) == maxMintSupply` (strict equality) or `>= maxMintSupply` (allow oversupply). Separately, add a time-based fallback completion: if `block.timestamp > mintEndTimestamp`, consider the mint finalized regardless of totalMinted, so ETH can still be relea"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(maxMintSupply|mintCap|MaxSupply|categories|Category|launchpad|Launchpad|Nft|NFT|mint\\s*\\(|totalMinted)'}, {'contract.has_func_matching': '(initialize|init|setup|configure)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(initialize|init|initNft|setup|configure|launch)[A-Z_]?\\w*$'}, {'function.has_param_of_type': '\\w+\\[\\]'}, {'function.signature_regex': 'uint256|uint'}, {'function.body_contains_regex': 'max(Mint)?Supply\\w*\\s*=|\\bsupply\\w*\\s*=\\s*\\w+\\.supply'}, {'function.body_not_contains_regex': 'totalSupply\\s*\\+=\\s*\\w+\\[\\s*i\\s*\\]\\.supply|sum\\s*\\+=\\s*\\w+\\.supply|require\\s*\\(\\s*\\w*Total\\w*\\s*>=\\s*max(Mint)?Supply'}, {'contract.has_func_body_matching': 'totalMinted\\s*==\\s*max(Mint)?Supply|minted\\s*>=\\s*max(Mint)?Supply'}, {'function.not_source_matches_regex': '(__\\w+_init\\s*\\(|_disableInitializers|Initializable\\.__|onlyInitializing\\s*\\{[^}]*\\}|revert\\s+Invalid)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — category-supply-below-mint-cap-locks-eth: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
