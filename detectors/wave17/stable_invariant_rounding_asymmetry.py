"""
stable-invariant-rounding-asymmetry — generated from reference/patterns.dsl/stable-invariant-rounding-asymmetry.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py stable-invariant-rounding-asymmetry.yaml
Source: defihacklabs/BalancerV2-2025-11+yETH-2025-12
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StableInvariantRoundingAsymmetry(AbstractDetector):
    ARGUMENT = "stable-invariant-rounding-asymmetry"
    HELP = "Stable-swap invariant helper uses asymmetric rounding across join and exit paths. Attacker loops join+exit to extract rounding dust in their direction."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/stable-invariant-rounding-asymmetry.yaml"
    WIKI_TITLE = "Stable invariant rounding asymmetric between join and exit"
    WIKI_DESCRIPTION = "Constant-product / constant-sum invariants require consistent rounding direction to protect the invariant. When joinPool rounds shares UP while exitPool rounds shares UP (or the reverse on the assets side), each trip through the pair accrues rounding error in the user's direction. Exploited repeatedly, the attacker drains the invariant buffer."
    WIKI_EXPLOIT_SCENARIO = "Balancer V2 ComposableStable 2025-11 ($120M): `_upscale` path used `divDown` during join calculation and `divUp` during exit calculation for the same value transformation, creating a ~1 wei rounding edge per pair of operations. Attacker flashloaned wstETH, performed thousands of join-exit cycles via atomic batch, and siphoned $120M of dust into their pocket."
    WIKI_RECOMMENDATION = "Every stable-math helper must document and enforce the protocol-favourable rounding direction: protocol always wins rounding (e.g., round DOWN what is paid to user, round UP what is paid to protocol). Unit test: for random (reserve, in) pair, join+immediate-exit must yield ≤ original input."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'StableMath|_calcOutGivenIn|calcBptOutGiven|invariant|_getInvariant|FixedPoint'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.body_contains_regex': 'divDown|divUp|divRound|mulDown|mulUp|FixedPoint\\.(div|mul)'}, {'function.name_matches': 'calc|compute|getInvariant|swap|BptOut|BptIn|OutGiven|InGiven'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — stable-invariant-rounding-asymmetry: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
