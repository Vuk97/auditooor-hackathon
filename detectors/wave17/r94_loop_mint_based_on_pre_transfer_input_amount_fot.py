"""
r94-loop-mint-based-on-pre-transfer-input-amount-fot — generated from reference/patterns.dsl/r94-loop-mint-based-on-pre-transfer-input-amount-fot.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-mint-based-on-pre-transfer-input-amount-fot.yaml
Source: loop-cycle-65-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopMintBasedOnPreTransferInputAmountFot(AbstractDetector):
    ARGUMENT = "r94-loop-mint-based-on-pre-transfer-input-amount-fot"
    HELP = "r94-loop-mint-based-on-pre-transfer-input-amount-fot"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-mint-based-on-pre-transfer-input-amount-fot.yaml"
    WIKI_TITLE = "r94-loop-mint-based-on-pre-transfer-input-amount-fot"
    WIKI_DESCRIPTION = "r94-loop-mint-based-on-pre-transfer-input-amount-fot"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-mint-based-on-pre-transfer-input-amount-fot"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(safeTransferFrom|safe_transfer_from)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(fund|deposit|mintShares|wrap|bridgeIn|lockAndMint)'}, {'function.source_matches_regex': 'safeTransferFrom\\s*\\([^;]*address\\s*\\(\\s*this\\s*\\)'}, {'function.source_matches_regex': '(_mint|mintShares|credit|mintTo)\\s*\\(\\s*\\w+\\s*,\\s*(amount|_amount|inputAmount)\\b'}, {'function.not_source_matches_regex': '(balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)\\s*-\\s*balanceBefore|received\\s*=\\s*balanceOf|receivedAmount)'}]

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
                info = [f, f" — r94-loop-mint-based-on-pre-transfer-input-amount-fot: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
