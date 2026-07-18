"""
refinance-does-not-pin-collateral-tokenid — generated from reference/patterns.dsl/refinance-does-not-pin-collateral-tokenid.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py refinance-does-not-pin-collateral-tokenid.yaml
Source: auditooor-R75-c4-lending-gondi-78
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RefinanceDoesNotPinCollateralTokenid(AbstractDetector):
    ARGUMENT = "refinance-does-not-pin-collateral-tokenid"
    HELP = "Refinance checks collateral CONTRACT address but not tokenId. Borrower swaps in a valuable tokenId during refinance to trade up from a floor NFT to a rare one at the lender's expense."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/refinance-does-not-pin-collateral-tokenid.yaml"
    WIKI_TITLE = "Refinance fails to pin collateral tokenId, enables NFT swap"
    WIKI_DESCRIPTION = "NFT lending protocols specify collateral as `(nftAddress, tokenId)`. A refinance should require that both identifiers match the existing loan. If the refinance path only checks `nftCollateralAddress` equality but not `nftCollateralTokenId`, a borrower can compose a refinance tx whose executionData references a DIFFERENT tokenId in the same collection — typically the highest-value rarity trait — wh"
    WIKI_EXPLOIT_SCENARIO = "Alice has 10 ETH loan against a floor BAYC (value ~11 ETH). She writes a refinanceFromLoanExecutionData with the same principalAddress / nftCollateralAddress but a tokenId belonging to Mutant-BAYC #1 (value 80 ETH) which she doesn't own. Actually simpler: she owns BAYC #8888 (rare trait, 50 ETH) and #1234 (floor, 11 ETH). She refinances a loan that was collateralized by #8888 against an offer whos"
    WIKI_RECOMMENDATION = "Add `require(_loan.nftCollateralTokenId == _loanExecutionData.tokenId, \"TokenIdMismatch\");` after the address checks in every refinance entrypoint. Consider hashing `(collection, tokenId)` together and comparing the hashes for less room for accidental omission."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(refinance|_refinance|LoanExecutionData)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(refinanceFromLoanExecutionData|_?refinanceFull|_?refinancePartial|refinance\\w*)'}, {'function.body_contains_regex': '(?i)_loan\\.(principalAddress|nftCollateralAddress)\\s*(==|!=)\\s*\\w+\\.(principalAddress|nftCollateralAddress)'}, {'function.body_not_contains_regex': '(?i)(_loan\\.nftCollateralTokenId\\s*(==|!=)\\s*\\w+\\.tokenId|_loan\\.tokenId\\s*==\\s*\\w+\\.tokenId|require\\s*\\([^)]*tokenId\\s*==)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — refinance-does-not-pin-collateral-tokenid: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
