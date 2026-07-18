"""
a-borrower-can-list-their-collateral-on-seaport-and-receive-almo — generated from reference/patterns.dsl/a-borrower-can-list-their-collateral-on-seaport-and-receive-almo.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-borrower-can-list-their-collateral-on-seaport-and-receive-almo.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ABorrowerCanListTheirCollateralOnSeaportAndReceiveAlmo(AbstractDetector):
    ARGUMENT = "a-borrower-can-list-their-collateral-on-seaport-and-receive-almo"
    HELP = "A borrower can list their collateral on Seaport and receive almost all the listing price without paying back their liens"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-borrower-can-list-their-collateral-on-seaport-and-receive-almo.yaml"
    WIKI_TITLE = "A borrower can list their collateral on Seaport and receive almost all the listing price without paying back their liens"
    WIKI_DESCRIPTION = "## Severity: Critical Risk\n\n## Context\n**File:** LienToken.sol#L480\n\n## Description\nWhen the collateral is listed on SeaPort by the borrower using `listForSaleOnSeaport`, `s.auctionData` is not populated. Thus, if that order gets fulfilled/matched and `ClearingHouse`'s fallback function gets called"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #7283: ## Severity: Critical Risk\n\n## Context\n**File:** LienToken.sol#L480\n\n## Description\nWhen the collateral is listed on SeaPort by the borrower using `listForSaleOnSeaport`, `s.auctionData` is not popula"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*listForSaleOnSeaport.*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.reads_state_var_matching': '.*(listForSaleOnSeaport|settleAuction|auctionData).*'}, {'function.body_contains_regex': '(?i)(seaport|fulfill|match|consideration|offer)'}, {'function.body_not_contains_regex': '(?i)(auctionData\\s*\\[|_?(accrue|update|sync|validate|check|refresh|record|populate)[A-Za-z0-9_]*\\s*\\()'}]

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
                info = [f, f" — a-borrower-can-list-their-collateral-on-seaport-and-receive-almo: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
