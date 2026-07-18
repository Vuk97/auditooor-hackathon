"""
r94-loop-ecdsa-high-s-malleability-not-rejected — generated from reference/patterns.dsl/r94-loop-ecdsa-high-s-malleability-not-rejected.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-ecdsa-high-s-malleability-not-rejected.yaml
Source: solodit-21369-spearbit-polygon-zkevm
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopEcdsaHighSMalleabilityNotRejected(AbstractDetector):
    ARGUMENT = "r94-loop-ecdsa-high-s-malleability-not-rejected"
    HELP = "r94-loop-ecdsa-high-s-malleability-not-rejected"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-ecdsa-high-s-malleability-not-rejected.yaml"
    WIKI_TITLE = "r94-loop-ecdsa-high-s-malleability-not-rejected"
    WIKI_DESCRIPTION = "r94-loop-ecdsa-high-s-malleability-not-rejected"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-ecdsa-high-s-malleability-not-rejected"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = {'contract.source_matches_regex': '(ECDSA|ecrecover|Verifier|Signature|TxProcessor)', 'function.name_matches': '(?i)(verifySignature|processTx|recoverSigner|ecrecoverSafe|_verifySig|checkSig)'}
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.source_matches_regex': '(ecrecover\\s*\\(|ECDSA\\.recover|ECDSA::recover|k256::ecdsa)'}, {'function.not_source_matches_regex': '(s\\s*>\\s*\\w*SECP256K1N_HALF|s\\s*>=\\s*\\w*SECP256K1N_HALF|\\w*sValue\\s*<=\\s*\\w*N_OVER_2|require\\s*\\(\\s*\\w*(s|sValue)\\s*<=\\s*\\w*HALF|checkLowS|lowS|canonicalSignature|EIP\\w*2\\s+malleability)'}, {'function.body_not_contains_regex': 'tryRecover|OpenZeppelin.*ECDSA|ECDSA\\.tryRecover'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — r94-loop-ecdsa-high-s-malleability-not-rejected: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
