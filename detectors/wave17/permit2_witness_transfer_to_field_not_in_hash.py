"""
permit2-witness-transfer-to-field-not-in-hash — generated from reference/patterns.dsl/permit2-witness-transfer-to-field-not-in-hash.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py permit2-witness-transfer-to-field-not-in-hash.yaml
Source: auditooor-R75-code4rena-2024-05-predy-17
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Permit2WitnessTransferToFieldNotInHash(AbstractDetector):
    ARGUMENT = "permit2-witness-transfer-to-field-not-in-hash"
    HELP = "permit2.permitWitnessTransferFrom is called but the protocol doesn't guard against signature reuse (multi-chain or post-revert capture) — the to field is mutable per call."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/permit2-witness-transfer-to-field-not-in-hash.yaml"
    WIKI_TITLE = "Permit2 witness transfer allows redirect of to field when signature is captured"
    WIKI_DESCRIPTION = "`permitWitnessTransferFrom` verifies the signature over (permit, witness, spender). The `transferDetails.to` and `transferDetails.requestedAmount` are NOT in the hash. If a protocol filler's tx reverts (bad price, stale order), the signature remains valid. On L2 chains where signatures are also valid cross-chain unless chainId is bound, an attacker picks up the leaked signature, calls the protocol"
    WIKI_EXPLOIT_SCENARIO = "Trader signs a permit2 witness for 1000 USDC to fill an order. Filler's tx reverts because price moved. Signature is now public (in a failed tx) but not consumed. Attacker on same (or different) chain calls the protocol with transferDetails.to = attacker. Protocol calls permit2; permit2 validates signature against the protocol as spender; 1000 USDC transferred to attacker."
    WIKI_RECOMMENDATION = "Switch to plain `permitTransferFrom` where the recipient is fixed in the permit. Alternatively, include chainId and a protocol-specific nullifier in the `witness` type, and require `transferDetails.to == witnessData.to`. Mark signatures as used on first verify to prevent post-revert reuse."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)_settleTrade|_fillOrder|executeOrder|_take'}, {'function.body_contains_regex': '(?i)permitWitnessTransferFrom|IPermit2\\.permitWitnessTransferFrom'}, {'function.body_not_contains_regex': '(?i)require\\s*\\(\\s*transferDetails\\.to\\s*==|permit\\(\\)\\s*\\.permitTransferFrom|_storeNullifier|usedSig\\['}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — permit2-witness-transfer-to-field-not-in-hash: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
