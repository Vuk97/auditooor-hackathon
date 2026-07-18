"""
polygon-mrc20-ecrecover-zero-address-accepted — generated from reference/patterns.dsl/polygon-mrc20-ecrecover-zero-address-accepted.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py polygon-mrc20-ecrecover-zero-address-accepted.yaml
Source: auditooor-R76-immunefi-polygon-$2.2M
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PolygonMrc20EcrecoverZeroAddressAccepted(AbstractDetector):
    ARGUMENT = "polygon-mrc20-ecrecover-zero-address-accepted"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: transferWithSig-style handler calls raw ecrecover and accepts the recovered signer without a visible address(0) rejection."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/polygon-mrc20-ecrecover-zero-address-accepted.yaml"
    WIKI_TITLE = "Raw ecrecover accepts address(0) on malformed signature"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Solidity ecrecover returns address(0) for malformed signatures. This row only proves the owned MRC20-style source shape where a transferWithSig-like entrypoint recovers `from` with raw ecrecover, forwards it into `_transfer(from, to, amount)`, and lacks a visible same-function zero-address rejection."
    WIKI_EXPLOIT_SCENARIO = "Polygon's MRC20 transferWithSig used ecrecovery without guarding zero-address recovery. Combined with a transfer path missing sender balance validation, a malformed signature recovered as 0x0 and let the attacker transfer a huge MATIC amount to themselves."
    WIKI_RECOMMENDATION = "Reject zero-address recovery immediately after raw ecrecover, or use a library recover helper that reverts on malformed signatures. Keep a balance check in the transfer primitive as a separate defense. Do not promote this row from fixture smoke alone."

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\becrecover\\s*\\('}, {'contract.source_matches_regex': '\\bmapping\\s*\\(\\s*address\\s*=>\\s*uint256\\s*\\)\\s+(?:public\\s+)?(?:balanceOf|balances|_balances)\\b'}, {'contract.source_matches_regex': '\\bfunction\\s+_transfer\\s*\\(\\s*address\\s+from\\s*,\\s*address\\s+to\\s*,\\s*uint256\\s+amount\\s*\\)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(transferWithSig|permitTransfer|signedTransfer|executeMetaTx)$'}, {'function.has_param_of_type': 'bytes'}, {'function.body_contains_regex': '\\becrecover\\s*\\('}, {'function.body_contains_regex': '\\b_transfer\\s*\\(\\s*from\\s*,\\s*to\\s*,\\s*amount\\s*\\)'}, {'function.body_not_contains_regex': '(require\\s*\\([^;{}]*(?:from|signer|recovered|recoveredSigner)\\s*!=\\s*address\\s*\\(\\s*0\\s*\\)|if\\s*\\([^;{}]*(?:from|signer|recovered|recoveredSigner)\\s*==\\s*address\\s*\\(\\s*0\\s*\\)[^;{}]*(?:revert|return))'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — polygon-mrc20-ecrecover-zero-address-accepted: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
