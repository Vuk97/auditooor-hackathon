"""
a-denial-of-ervice-attack-can-obstruct-flop-auctions — generated from reference/patterns.dsl/a-denial-of-ervice-attack-can-obstruct-flop-auctions.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-denial-of-ervice-attack-can-obstruct-flop-auctions.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ADenialOfErviceAttackCanObstructFlopAuctions(AbstractDetector):
    ARGUMENT = "a-denial-of-ervice-attack-can-obstruct-flop-auctions"
    HELP = "A Denial of ervice attack can obstruct Flop auctions"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-denial-of-ervice-attack-can-obstruct-flop-auctions.yaml"
    WIKI_TITLE = "A Denial of ervice attack can obstruct Flop auctions"
    WIKI_DESCRIPTION = "## Description\n\nIn order to initiate a Flop auction, the Vow contract requires that it have a zero Dai balance within the Vat. An unprivileged user can send a small amount of Dai to the Vow within the Vat. In doing so, the user prevents the Vow from initiating a Flop auction until it calls `heal`. T"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #17063: ## Description\n\nIn order to initiate a Flop auction, the Vow contract requires that it have a zero Dai balance within the Vat. An unprivileged user can send a small amount of Dai to the Vow within the"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches_regex': '.*(heal|move|flop).*'}, {'function.writes_state_var_matching_regex': '.*(flop|heal|move).*'}, {'function.body_not_contains_regex': '(?i)require\\s*\\([^)]*(flop|heal|move)[^)]*\\)|assert\\s*\\([^)]*(flop|heal|move)[^)]*\\)'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-denial-of-ervice-attack-can-obstruct-flop-auctions: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
