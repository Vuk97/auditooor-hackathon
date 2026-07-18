"""
hexens-rfq-taker-signature-no-deadline-reused-quote — generated from reference/patterns.dsl/hexens-rfq-taker-signature-no-deadline-reused-quote.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py hexens-rfq-taker-signature-no-deadline-reused-quote.yaml
Source: auditooor-R75-hexens-Hashflow-1inchFusion-RFQ
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HexensRfqTakerSignatureNoDeadlineReusedQuote(AbstractDetector):
    ARGUMENT = "hexens-rfq-taker-signature-no-deadline-reused-quote"
    HELP = "RFQ/Fusion settlement verifies a market-maker signature over the quote but does not check an expiry — an attacker can replay a once-quoted rate months later when spot has drifted, draining the maker."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/hexens-rfq-taker-signature-no-deadline-reused-quote.yaml"
    WIKI_TITLE = "RFQ settlement accepts maker-signed quote without expiry/deadline enforcement"
    WIKI_DESCRIPTION = "RFQ protocols (Hashflow, 0x v4, 1inch Fusion) let an off-chain market-maker sign a bilateral quote — `sig = sign(maker, {tokenIn, tokenOut, amountIn, amountOut, nonce, deadline})` — and any taker can present the sig + fill it. Correctness requires the on-chain settlement to (a) verify the sig, (b) enforce `block.timestamp <= deadline`, (c) ensure the nonce is unused. When the deadline check is mis"
    WIKI_EXPLOIT_SCENARIO = "Hashflow-style pool: maker signs quote { sell 1 WETH, buy 2000 USDC, nonce 42, no-deadline-check-onchain } at t=0 when ETH=$2000. Taker A fills immediately at fair price. But the same signed struct is valid at t=6months when ETH=$4000: the nonce field would prevent re-use by the same filler, but the settlement's nonce tracking is per-maker-per-nonce, so if the maker ever reuses nonce 42 in a new q"
    WIKI_RECOMMENDATION = "Make `deadline` (or `validUntil`) a required field of the EIP-712 typed-data struct, hashed into the signature. On settlement: `require(quote.deadline >= block.timestamp, 'expired');`. Enforce nonce uniqueness via bitmap or incrementing counter per maker. Advise makers to use short expiries (60-300s"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Fusion|Hashflow|RFQ|Quote|Settlement'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'fillOrder|settleRFQ|_verifyQuote|executeQuote|takeQuote|fill|settle'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': 'ecrecover|ECDSA\\.recover|_hashTypedDataV4'}, {'function.body_contains_regex': 'marketMaker|maker\\.|quote\\.maker'}, {'function.body_not_contains_regex': 'quote\\.expiry|quote\\.deadline|block\\.timestamp\\s*(<=|<)\\s*(expiry|deadline|validUntil)|validUntil|expireAt'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — hexens-rfq-taker-signature-no-deadline-reused-quote: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
