"""
rental-type-flag-ignored-in-operation-handlers — generated from reference/patterns.dsl/rental-type-flag-ignored-in-operation-handlers.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rental-type-flag-ignored-in-operation-handlers.yaml
Source: auditooor-R75-code4rena-2024-10-coded-estate-7
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RentalTypeFlagIgnoredInOperationHandlers(AbstractDetector):
    ARGUMENT = "rental-type-flag-ignored-in-operation-handlers"
    HELP = "Rental handler iterates the shared rentals vector without filtering on rental_type — short-term operation can match a long-term entry, possibly with a different denom."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rental-type-flag-ignored-in-operation-handlers.yaml"
    WIKI_TITLE = "Rental handlers ignore rental_type discriminant, cross-processing short-term and long-term entries"
    WIKI_DESCRIPTION = "Solidity fixture-port/source-shape proof only: a handler iterates a shared `rentals` collection and matches tenant/period without checking the rental-type discriminant. The original CodedEstate finding was Rust/CosmWasm-shaped; this Slither detector does not prove backend-complete coverage."
    WIKI_EXPLOIT_SCENARIO = "A long-term rental finalizer loops through a mixed rental list and matches a short-term entry because the handler never filters on `rentalType`. Real exploitability, denom mismatch, and payout impact still need target-specific source/runtime proof."
    WIKI_RECOMMENDATION = "Filter shared rental entries by the expected discriminant before processing, or split short-term and long-term bookings into separate storage collections."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?is)\\brentals\\b.*\\b(rental_type|rentalType|is_short|isShort|kind)\\b|\\b(rental_type|rentalType|is_short|isShort|kind)\\b.*\\brentals\\b'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(finalize|cancel)\\w*Rental'}, {'function.body_contains_regex': '(?i)\\.rentals\\.iter|\\.rentals\\[|for\\s+\\w+\\s+in\\s+\\w*rentals'}, {'function.body_contains_regex': '(?is)(tenant|landlord|renter|owner).{0,240}(period|start|end|month|day|duration)|(period|start|end|month|day|duration).{0,240}(tenant|landlord|renter|owner)'}, {'function.body_not_contains_regex': '(?i)(rental_type|rentalType|\\.kind|is_short|isShort)\\s*(==|!=)|item\\.is_short|item\\.isShort|if\\s*\\([^)]*(rental_type|rentalType|kind|is_short|isShort)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — rental-type-flag-ignored-in-operation-handlers: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
