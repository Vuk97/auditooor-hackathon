"""
r94-loop-sig-verify-message-hash-missing-nonce-replay — generated from reference/patterns.dsl/r94-loop-sig-verify-message-hash-missing-nonce-replay.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-sig-verify-message-hash-missing-nonce-replay.yaml
Source: solodit-51938-halborn-analog-labs-gateway
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopSigVerifyMessageHashMissingNonceReplay(AbstractDetector):
    ARGUMENT = "r94-loop-sig-verify-message-hash-missing-nonce-replay"
    HELP = "r94-loop-sig-verify-message-hash-missing-nonce-replay"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-sig-verify-message-hash-missing-nonce-replay.yaml"
    WIKI_TITLE = "r94-loop-sig-verify-message-hash-missing-nonce-replay"
    WIKI_DESCRIPTION = "r94-loop-sig-verify-message-hash-missing-nonce-replay"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-sig-verify-message-hash-missing-nonce-replay"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = {'contract.source_matches_regex': '(Gateway|Forwarder|MetaTx|Verifier|SignedExecutor|Bridge)', 'function.name_matches': '(?i)(updateKeys|verifyMessage|executeSigned|processSignedOp|relayedCall)', 'function.source_matches_regex': '(verifySignature|ecrecover\\s*\\(|ECDSA\\.recover|_verifySig|ecdsaRecover)', 'function.not_source_matches_regex': '(nonce\\s*\\+=\\s*1|nonces\\s*\\[\\s*\\w+\\s*\\]\\s*=|require\\s*\\(\\s*\\w*nonce\\s*==|used\\[\\s*\\w*hash\\s*\\]\\s*=\\s*true|usedSigs\\.insert|processedMessages\\[)'}
    _MATCH = ['contract.source_matches_regex', 'function.name_matches', 'function.source_matches_regex', 'function.not_source_matches_regex']

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
                info = [f, f" — r94-loop-sig-verify-message-hash-missing-nonce-replay: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
