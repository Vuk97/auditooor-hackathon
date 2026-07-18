"""
burn-deletes-active-rental-deposits — generated from reference/patterns.dsl/burn-deletes-active-rental-deposits.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py burn-deletes-active-rental-deposits.yaml
Source: auditooor-R75-code4rena-2024-10-coded-estate-2
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BurnDeletesActiveRentalDeposits(AbstractDetector):
    ARGUMENT = "burn-deletes-active-rental-deposits"
    HELP = "burn removes the token and its attached rental/bid vectors without first requiring them to be empty — tenants' deposits become unrecoverable."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/burn-deletes-active-rental-deposits.yaml"
    WIKI_TITLE = "Burning a token discards attached rental/bid deposits, locking third-party funds"
    WIKI_DESCRIPTION = "An NFT contract stores rental and bid records as vectors on the token struct. `burn` checks only ownership/approval, then deletes the entire TokenInfo. If tenants have active prepaid rentals (or open bids with escrowed funds), the records are lost and the refund/cancellation paths, which require matching a rental entry, permanently revert — tenants' funds stay in the contract forever."
    WIKI_EXPLOIT_SCENARIO = "Tenant prepays 10 SOL for a month-long rental. Landlord decides to burn the token mid-rental (griefing). After burn, tenant calls `cancelRental` → contract can't find the rental record → call reverts. 10 SOL is stuck in the pooled contract balance, reachable only by an unrelated landlord's finalize call."
    WIKI_RECOMMENDATION = "In `burn`, require `token.rentals.len() == 0 && token.bids.len() == 0`. Alternatively, auto-refund all pending deposits in a loop before burning."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^burn$|burnNft|burnToken|destroy\\w*'}, {'function.body_contains_regex': '(?i)self\\.tokens\\.remove|_burn\\(|delete\\s+tokens\\s*\\['}, {'function.body_not_contains_regex': '(?i)rentals\\.is_empty|bids\\.is_empty|require\\s*\\([^)]*\\.length\\s*==\\s*0|no_active_rentals|no_pending_bids'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — burn-deletes-active-rental-deposits: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
