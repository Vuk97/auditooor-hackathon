"""
perp-price-not-signature-verified-in-limit-close — generated from reference/patterns.dsl/perp-price-not-signature-verified-in-limit-close.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-price-not-signature-verified-in-limit-close.yaml
Source: auditooor-R75-c4-2022-12-tigris-H614
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpPriceNotSignatureVerifiedInLimitClose(AbstractDetector):
    ARGUMENT = "perp-price-not-signature-verified-in-limit-close"
    HELP = "Function calls `getVerifiedPrice(priceData, sig)` (which returns nothing or is treated as a void check), then reads `priceData.price` directly. A malicious/mismatched priceData struct passes the signature check for OTHER fields while `price` is the attacker's choice — limit-close triggers at any pri"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-price-not-signature-verified-in-limit-close.yaml"
    WIKI_TITLE = "Limit-close reads priceData.price directly after a verifyPrice call that never wrote to it"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row preserves the Tigris H-614 limit-close shape where a caller invokes `getVerifiedPrice(asset, priceData, sig, 0)` but then still branches on `_priceData.price` instead of a verified return value. The local proof distinguishes only that owned shape from a clean variant that stores and uses the verified price."
    WIKI_EXPLOIT_SCENARIO = "(1) Alice has a limit-close at takeProfit = 3500 on a long entered at 3000. Mark is currently 3100. (2) Attacker crafts a PriceData struct with price=3600 (above her TP), timestamp=now, and a signature that covers only `(asset, timestamp)` — because `verifyPrice` implementation accidentally omits price from the digest (or the bug is a separate helper). (3) Attacker calls `limitClose(aliceId, true,"
    WIKI_RECOMMENDATION = "ALWAYS use the return value of `getVerifiedPrice`, not the input struct: `uint256 verifiedPrice = getVerifiedPrice(asset, priceData, sig, 0);`. If the helper can't return, re-fetch the canonical price or make the helper write the verified value somewhere the caller reads. Keep submission_posture NOT"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(limitClose|_limitClose|closePosition|priceData|getVerifiedPrice|TradingExtension)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(_limitClose|limitClose|_closePosition|triggerClose|takeProfit|stopLoss)'}, {'function.body_contains_regex': 'getVerifiedPrice\\s*\\([^)]*_priceData[^)]*_signature'}, {'function.body_contains_regex': '_priceData\\.price'}, {'function.body_not_contains_regex': '(verifiedPrice\\s*=\\s*getVerifiedPrice|uint256?\\s+_price\\s*=\\s*getVerifiedPrice|_price\\s*=\\s*TradingLibrary\\.verifyPrice)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-price-not-signature-verified-in-limit-close: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
