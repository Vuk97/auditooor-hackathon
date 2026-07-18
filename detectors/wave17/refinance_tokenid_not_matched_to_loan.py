"""
refinance-tokenid-not-matched-to-loan — generated from reference/patterns.dsl/refinance-tokenid-not-matched-to-loan.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py refinance-tokenid-not-matched-to-loan.yaml
Source: auditooor-R75-code4rena-2024-04-gondi-54
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RefinanceTokenidNotMatchedToLoan(AbstractDetector):
    ARGUMENT = "refinance-tokenid-not-matched-to-loan"
    HELP = "Refinance validates the new-offer tokenId against lender approvals but never asserts it equals the existing loan's collateral tokenId — borrower can trick lenders into accepting the wrong NFT."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/refinance-tokenid-not-matched-to-loan.yaml"
    WIKI_TITLE = "Refinance does not tie new-loan tokenId to old-loan collateral, enabling bait-and-switch"
    WIKI_DESCRIPTION = "In `refinanceFromLoanExecutionData` the new-loan processor accepts `executionData.tokenId` from calldata and validates it against the lender's offer/validators. The NFT itself is already in escrow from the old loan and is not re-transferred. There is no check that `executionData.tokenId == oldLoan.nftCollateralTokenId`. A borrower whose old loan is backed by a rare NFT (tokenId 42) can submit an e"
    WIKI_EXPLOIT_SCENARIO = "Old loan: 10 ETH against rare NFT #42. Borrower posts fake execution data claiming tokenId = 1. A lender has a blanket offer accepting all tokenIds in a collection at 5 ETH. Validator passes. New loan opens at 5 ETH against 'tokenId 1' but the escrow still holds #42. Borrower defaults and walks away."
    WIKI_RECOMMENDATION = "At the top of refinance, require `executionData.tokenId == loan.nftCollateralTokenId`. Better: drop tokenId from the execution data entirely and always read it from the old loan struct."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)refinance\\w*|rollover\\w*|extend\\w*Loan'}, {'function.body_contains_regex': '(?i)executionData\\.tokenId|newLoan\\.tokenId|offers?\\[.*\\]\\.tokenId'}, {'function.body_not_contains_regex': '(?i)require\\s*\\([^)]*executionData\\.tokenId\\s*==\\s*\\w*loan\\.nftCollateralTokenId|require\\s*\\([^)]*newTokenId\\s*==\\s*oldTokenId'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — refinance-tokenid-not-matched-to-loan: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
