"""
multisource-add-tranche-no-borrower-consent — generated from reference/patterns.dsl/multisource-add-tranche-no-borrower-consent.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py multisource-add-tranche-no-borrower-consent.yaml
Source: auditooor-R75-c4-lending-gondi-52
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MultisourceAddTrancheNoBorrowerConsent(AbstractDetector):
    ARGUMENT = "multisource-add-tranche-no-borrower-consent"
    HELP = "addNewTranche validates only the lender signature, skips the borrower consent and the strictly-better check. Any lender can force additional principal at unfavorable terms onto the borrower."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/multisource-add-tranche-no-borrower-consent.yaml"
    WIKI_TITLE = "addNewTranche forces debt onto borrower without consent or strictly-better check"
    WIKI_DESCRIPTION = "Multi-source NFT lending supports multi-tranche loans: one loan can have several lenders with different APRs and seniorities. The `refinance*` path requires the new offer to be strictly better than the existing loan for the borrower (`_checkStrictlyBetter`) when initiated by a lender. The `addNewTranche` variant was intended for borrower-initiated tranche additions, but the implementation only ver"
    WIKI_EXPLOIT_SCENARIO = "Alice borrows 10 ETH against BAYC at 5% APR. Lender Eve calls `addNewTranche(offer={principal: 5 ETH, apr: 1000 bps}, loan, eveSig)`. Function passes lender sig check, skips borrower consent, skips strictly-better. Alice's loan is now 15 ETH at a weighted higher APR, with a new Eve-owned senior tranche. Alice must repay the extra 5 ETH + higher interest or be liquidated; Eve keeps the BAYC."
    WIKI_RECOMMENDATION = "Require either `msg.sender == _loan.borrower` OR `_checkSignature(_loan.borrower, offer.hash(), borrowerSig);` OR run `_checkStrictlyBetter(_loan, offer)` so lender-initiated additions cannot worsen the loan. Better: gate addNewTranche behind a borrower-signed approval for every change."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(tranche|renegotiationOffer|_addNewTranche|MultiSourceLoan)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(addNewTranche|_?addNewTranche|refinancePartial)'}, {'function.body_contains_regex': '(?i)_addNewTranche\\s*\\(|loanWithTranche|principalAmount\\s*\\+=\\s*_renegotiationOffer'}, {'function.body_not_contains_regex': '(?i)(msg\\.sender\\s*==\\s*_loan\\.borrower|_checkSignature\\s*\\(\\s*_loan\\.borrower|borrowerSig|_checkStrictlyBetter|_checkTranchesStrictly|borrowerConsent)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — multisource-add-tranche-no-borrower-consent: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
