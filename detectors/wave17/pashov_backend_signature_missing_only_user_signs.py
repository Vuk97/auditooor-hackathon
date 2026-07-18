"""
pashov-backend-signature-missing-only-user-signs — generated from reference/patterns.dsl/pashov-backend-signature-missing-only-user-signs.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pashov-backend-signature-missing-only-user-signs.yaml
Source: auditooor-R75-pashov-Theo-ThUSDMinter-L07
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PashovBackendSignatureMissingOnlyUserSigns(AbstractDetector):
    ARGUMENT = "pashov-backend-signature-missing-only-user-signs"
    HELP = "Order verification recovers only the user-side signature; the 'backend determines exchange rate off-chain' docs claim a co-signer, but the contract never verifies it — user can craft any favorable rate and sign themselves."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pashov-backend-signature-missing-only-user-signs.yaml"
    WIKI_TITLE = "Intent/Order verification recovers user signature only — missing backend co-signature"
    WIKI_DESCRIPTION = "RFQ-style mint/redeem/swap designs where a backend computes the exchange rate and a user signs the final Order typically require TWO signatures on-chain: (1) the user attesting to their consent and parameters, (2) the backend attesting that the parameters match its off-chain quote. Pre-fix contracts often verify only the user's signature against `order.signer`, trusting that the user 'would not si"
    WIKI_EXPLOIT_SCENARIO = "ThUSDMinter: Malicious MINTER_ROLE holder constructs Order{signer=self, thusd_amount=10_000_000e18, collateral_amount=1e6, expiry=far_future}, hashes it, signs with own key, submits. `_validateOrder`: `recovered = ECDSA.recover(hash, sig); if (recovered != order.signer) revert;` — passes, because the user signed their own order. Mint goes through: 1 USDC in, 10M ThUSD out. The backend never author"
    WIKI_RECOMMENDATION = "Add a second signature field (`bytes backendSignature`) to the Order wire format. In `_validateOrder`, recover backendSignature over the same orderHash and require `backendRecovered == authorizedBackendSigner` (a state variable, settable by governance). Backend's private key signs after it has verif"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Order|hashOrder|ECDSA\\.recover|intent|signature'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'mint|redeem|fill|execute|settle|swap|executeOrder'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': 'ECDSA\\.recover\\s*\\(\\s*orderHash\\s*,\\s*signature\\s*\\)|_verifyOrderSig'}, {'function.body_contains_regex': 'recovered\\s*!=\\s*order\\.signer|!=\\s*order\\.user|!=\\s*intent\\.signer'}, {'function.body_not_contains_regex': 'backendSig|oracleSig|serverSig|authorizedSigner|BACKEND_SIGNER_ROLE|ecrecover\\s*\\(\\s*orderHash\\s*,\\s*backend|verifySecondary'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pashov-backend-signature-missing-only-user-signs: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
