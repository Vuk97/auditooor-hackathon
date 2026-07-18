"""
signature-missing-expiration — generated from reference/patterns.dsl/signature-missing-expiration.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py signature-missing-expiration.yaml
Source: solodit-signature-replay-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SignatureMissingExpiration(AbstractDetector):
    ARGUMENT = "signature-missing-expiration"
    HELP = "Signature-verifying function (ecrecover / SignatureChecker) has no deadline or expiry bound into the digest — old unfilled signed payloads remain executable indefinitely at stale conditions."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/signature-missing-expiration.yaml"
    WIKI_TITLE = "Signature replay via missing expiration / deadline"
    WIKI_DESCRIPTION = "Signed off-chain payloads (limit orders, permits, meta-transactions, voucher claims) must carry an explicit `deadline` / `expiry` / `validUntil` that is checked against `block.timestamp` inside the on-chain verifier. Without it, a signature that was valid-but-unfilled weeks or months ago becomes executable the moment conditions flip in the signer's disfavor: an off-chain limit order at $1500 ETH i"
    WIKI_EXPLOIT_SCENARIO = "A user signs an off-chain limit order selling 100 WETH at 1500 USDC/WETH. The order is never filled because the market does not reach that price. Six months later ETH briefly wicks down through 1500; a searcher submits the still-valid signature. The signer's WETH is sold at prices that have long since been economically stale. Because the contract's `fillOrder(...)` only verifies ecrecover + nonce "
    WIKI_RECOMMENDATION = "Bind every signed payload to an explicit `deadline` parameter and enforce `require(block.timestamp <= deadline, 'expired')` inside the verifier. Include the deadline in the EIP-712 struct hash so it is authenticated, not merely asserted. Prefer OpenZeppelin Permit / EIP-2612 style where `deadline` i"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_body_matching': '(ecrecover\\s*\\(|SignatureChecker\\.|isValidSignatureNow)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': {'regex': '(ecrecover\\s*\\(|SignatureChecker\\.|isValidSignatureNow)'}}, {'function.body_not_contains_regex': '(deadline|expiry|expir|\\bvalidUntil\\b|block\\.timestamp\\s*(<=?|>=?)\\s*\\w*(deadline|expir|validUntil|issuedAt))'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — signature-missing-expiration: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
