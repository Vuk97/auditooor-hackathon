"""
certora-makerdao-vat-dai-sin-conservation — generated from reference/patterns.dsl/certora-makerdao-vat-dai-sin-conservation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-makerdao-vat-dai-sin-conservation.yaml
Source: certora-dss-vat/debtConservation
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraMakerdaoVatDaiSinConservation(AbstractDetector):
    ARGUMENT = "certora-makerdao-vat-dai-sin-conservation"
    HELP = "Vat-like mutator writes `dai` or `sin` without the matching paired write — breaks Certora `debtConservation` invariant (sum(dai) + debt == sum(sin) + vice)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-makerdao-vat-dai-sin-conservation.yaml"
    WIKI_TITLE = "Maker Vat mutator breaks debt/sin conservation invariant"
    WIKI_DESCRIPTION = "MakerDAO's `Vat` maintains the global ledger identity `sum(dai[u]) + debt == sum(sin[u]) + vice`. Every official operation (frob creates dai and debt; suck creates dai and sin; heal burns dai against sin; grab moves bad debt to sin) preserves the sum. A custom mutator that credits a user's `dai[]` (IOU) without the matching sin/debt entry mints unbacked stablecoin. A mutator that zeroes a `sin[]` "
    WIKI_EXPLOIT_SCENARIO = "A governance-controlled `give(user, amount)` is added to Vat, writing `dai[user] += amount` to reward an LP, without updating `debt` or `sin`. The conservation invariant breaks — the protocol now owes more DAI than it has sin to back. Surplus Auction lot is already set to dump this phantom dai; a keeper mints MKR tokens from thin air, effectively inflating governance supply against backing that do"
    WIKI_RECOMMENDATION = "Keep all Vat mutation in the canonical operations (frob, fork, grab, heal, suck, move). If new operations are required, they must touch dai/sin/debt/vice in matched pairs so the sum is preserved. Prove the conservation invariant with Certora on every such path."

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i)(^|\\b)(dai|sin|debt|vice|Art|ink|urns|gem)\\b'}, {'contract.source_matches_regex': '(?i)(frob|grab|suck|heal|vat|dss|maker)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^(frob|fork|grab|heal|suck|move|slip|flux|drip|adjust|_debtOp|_moveDai)[A-Za-z0-9_]*'}, {'function.writes_storage_matching': '(?i)(^|\\b)(dai|sin|debt|vice)\\b'}, {'function.body_not_contains_regex': '(?i)(debt\\s*(=|\\+=|-=)\\s*[^;]*sin|sin\\s*(=|\\+=|-=)\\s*[^;]*dai|vice\\s*(=|\\+=|-=))'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — certora-makerdao-vat-dai-sin-conservation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
