"""
a-malicious-collateralized-nft-token-can-block-liquidation-and-a — generated from reference/patterns.dsl/a-malicious-collateralized-nft-token-can-block-liquidation-and-a.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-collateralized-nft-token-can-block-liquidation-and-a.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousCollateralizedNftTokenCanBlockLiquidationAndA(AbstractDetector):
    ARGUMENT = "a-malicious-collateralized-nft-token-can-block-liquidation-and-a"
    HELP = "A malicious collateralized NFT token can block liquidation and also epoch processing for public vaults"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-collateralized-nft-token-can-block-liquidation-and-a.yaml"
    WIKI_TITLE = "A malicious collateralized NFT token can block liquidation and also epoch processing for public vaults"
    WIKI_DESCRIPTION = "Liquidation code that approves a borrower-supplied collateral NFT inline before creating or settling an auction can be griefed by a malicious ERC721 implementation. If the NFT's `approve` path reverts, the liquidation reverts too, and any public-vault epoch workflow waiting on the liquidation can stall."
    WIKI_EXPLOIT_SCENARIO = "A borrower escrows a custom ERC721 whose `approve(spender, tokenId)` always reverts once liquidation starts. The liquidation path reaches `collateralToken.approve(seaport, tokenId)` and reverts every time, so the lien never clears and the public vault keeps its epoch blocked behind the open liquidation."
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(liquidat|auction|seaport|processEpoch|collateral)'}]
    _MATCH = [{'function.name_matches': '(?i)(liquidate|startAuction|createAuction|settleAuction|processEpoch|CollateralToken)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.has_high_level_call_named': '^approve$'}, {'function.body_contains_regex': '(?i)(seaport|auction|liquidat|epoch)'}, {'function.body_contains_regex': '(?i)(tokenId|collateralId)'}, {'function.body_not_contains_regex': '(?i)\\btry\\s+\\w+\\.approve\\s*\\(|_?(queue|sync|update|record|mark)[A-Za-z0-9_]*(Auction|Epoch|Approval|Liquidation)|claimable|pendingApproval'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — a-malicious-collateralized-nft-token-can-block-liquidation-and-a: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
