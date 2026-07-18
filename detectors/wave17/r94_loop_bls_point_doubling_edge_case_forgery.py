"""
r94-loop-bls-point-doubling-edge-case-forgery — generated from reference/patterns.dsl/r94-loop-bls-point-doubling-edge-case-forgery.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-bls-point-doubling-edge-case-forgery.yaml
Source: solodit-21284-trailofbits-succinct-telepathy
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopBlsPointDoublingEdgeCaseForgery(AbstractDetector):
    ARGUMENT = "r94-loop-bls-point-doubling-edge-case-forgery"
    HELP = "r94-loop-bls-point-doubling-edge-case-forgery"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-bls-point-doubling-edge-case-forgery.yaml"
    WIKI_TITLE = "r94-loop-bls-point-doubling-edge-case-forgery"
    WIKI_DESCRIPTION = "r94-loop-bls-point-doubling-edge-case-forgery"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-bls-point-doubling-edge-case-forgery"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(BLS|BN254|G1|G2|Curve|EllipticCurve|bls12|CircomPoint)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(doublePoint|pointDoubling|ecDouble|g1Double|g2Double|blsDouble|doubling|doubleStep)'}, {'function.source_matches_regex': '(3\\s*\\*\\s*\\w*x\\s*\\*\\s*\\w*x|3\\s*\\*\\s*\\w*x\\.square|2\\s*\\*\\s*\\w*y\\b|slope\\s*=|lambda\\s*=|lam\\s*=)'}, {'function.not_source_matches_regex': '(isInfinity|pointAtInfinity|isIdentity|isZero\\s*\\(\\s*\\)|\\w*y\\s*==\\s*0|\\w*y\\.isZero|P\\s*==\\s*-\\s*P|negPoint|checkInfinity)'}]

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
                info = [f, f" — r94-loop-bls-point-doubling-edge-case-forgery: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
