"""
fx-euler-protocol-fee-share-unbounded — generated from reference/patterns.dsl/fx-euler-protocol-fee-share-unbounded.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-euler-protocol-fee-share-unbounded.yaml
Source: github:euler-xyz/euler-vault-kit@52c07b3
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxEulerProtocolFeeShareUnbounded(AbstractDetector):
    ARGUMENT = "fx-euler-protocol-fee-share-unbounded"
    HELP = "protocolFeeShare() does not guard against a zero feeReceiver address or a protocol-configured share above the protocol maximum. A zero feeReceiver should return CONFIG_SCALE (all fees burned) and the returned share should be capped at MAX_PROTOCOL_FEE_SHARE."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-euler-protocol-fee-share-unbounded.yaml"
    WIKI_TITLE = "protocolFeeShare() missing zero-receiver and max-share guards — unbounded fee extraction"
    WIKI_DESCRIPTION = "Fee share view functions that directly return protocolConfig.protocolFeeConfig() without validating the feeReceiver or capping the returned percentage allow the protocol config to be misconfigured in two ways: (1) zero feeReceiver with non-zero share silently routes fees to address(0), and (2) a malicious/misconfigured protocol config returning above MAX_PROTOCOL_FEE_SHARE extracts more fees than "
    WIKI_EXPLOIT_SCENARIO = "Euler Cantina-207 (2024): feeReceiver is set to address(0) but protocolFeeConfig returns 5%. All vault fee accruals that check protocolFeeShare() send 5% to address(0), permanently burning protocol revenue."
    WIKI_RECOMMENDATION = "Add: (1) `if (feeReceiver == address(0)) return CONFIG_SCALE;` before calling protocolFeeConfig, and (2) `if (protocolShare > MAX_PROTOCOL_FEE_SHARE) return MAX_PROTOCOL_FEE_SHARE;` after."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^protocolFeeShare$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^protocolFeeShare$'}, {'function.body_contains_regex': 'protocolFeeConfig|protocolShare|feeConfig'}, {'function.body_not_contains_regex': 'feeReceiver.*==.*address\\(0\\)|MAX_PROTOCOL_FEE_SHARE'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-euler-protocol-fee-share-unbounded: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
