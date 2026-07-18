"""
limit-order-price-frontrun — generated from reference/patterns.dsl/limit-order-price-frontrun.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py limit-order-price-frontrun.yaml
Source: solodit-cluster-C0045
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LimitOrderPriceFrontrun(AbstractDetector):
    ARGUMENT = "limit-order-price-frontrun"
    HELP = "Off-chain-signed limit order read from mutable storage inside fillOrder/executeOrder without any hash/digest binding — order creator can rotate limitPrice/duration between signing and fill and rug the executor."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/limit-order-price-frontrun.yaml"
    WIKI_TITLE = "Limit-order price front-run: mutable post-sign fields without content hash"
    WIKI_DESCRIPTION = "Protocols that accept an off-chain-signed Order struct and keep the struct mutable after signing (limitPrice, duration, makerAmount, takerAmount) expose the executor to front-running. If fillOrder does not verify a keccak256/EIP-712 digest that covers the mutable fields, the maker can observe the pending fill in the mempool and swap in worse terms before inclusion, or cancel an ITM order at a give"
    WIKI_EXPLOIT_SCENARIO = "1) Maker signs an Order with limitPrice = P0 and broadcasts it off-chain. 2) Executor submits fillOrder(order, sig). 3) Maker front-runs by calling updateOrder (or equivalent) to rotate limitPrice to P1 far away from market. 4) fillOrder reads the now-mutated limitPrice, recomputes proceeds using P1, and the executor fills at disastrous terms. Alternatively, the maker cancels when the order is in-"
    WIKI_RECOMMENDATION = "Bind the signature to a keccak256/EIP-712 digest that covers every price-relevant field of the Order (limitPrice, makerAmount, takerAmount, expiry). Verify the digest inside fillOrder before reading those fields. Prefer OpenZeppelin EIP712 + a nonce/cancellation map keyed by orderHash. Consider maki"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'order|limitOrder|Order'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'fillOrder|executeOrder|fill|execute|matchOrder'}, {'function.body_contains_regex': 'order\\.|\\.limitPrice|\\.makerAmount|\\.takerAmount'}, {'function.body_not_contains_regex': 'keccak256\\s*\\(|hashOrder|orderHash|orderDigest|typedDataHash'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — limit-order-price-frontrun: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
