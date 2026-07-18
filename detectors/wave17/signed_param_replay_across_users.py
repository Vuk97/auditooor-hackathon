"""
signed-param-replay-across-users — generated from reference/patterns.dsl/signed-param-replay-across-users.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py signed-param-replay-across-users.yaml
Source: solodit/sherlock/autonomint-H5-45458
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SignedParamReplayAcrossUsers(AbstractDetector):
    ARGUMENT = "signed-param-replay-across-users"
    HELP = "Signature on a numeric admin-provided parameter (cumulative value / discount / price) omits msg.sender and position id from the signed hash. Any user can replay a favorable tuple pulled from another account's on-chain transaction to inflate their own payout."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/signed-param-replay-across-users.yaml"
    WIKI_TITLE = "Signed numeric parameter replay: hash omits caller and position ID"
    WIKI_DESCRIPTION = "An admin off-chain oracle signs (value, nonce) tuples that gate a profit / discount / price calculation on-chain. The signature-verification hash is built from `(value, nonce)` alone, without mixing in `msg.sender`, the deposit index, or a per-user nonce counter. Because all historical (value, nonce, sig) tuples are visible on-chain, any user with an open position can pick the most favorable one e"
    WIKI_EXPLOIT_SCENARIO = "Protocol signs an `excessProfitCumulativeValue` per user off-chain based on per-user deposit metadata. User A's withdrawal uses a small cumulativeValue (high profit for A). User B observes A's tx, copies `(cumulativeValue=A, nonce=N, sig=S)` into their own `withdraw(B_index, cumulativeValue=A, nonce=N, sig=S)`. `_verify` passes — the hash contained no binding to A — and B's profit is computed with"
    WIKI_RECOMMENDATION = "Include `msg.sender`, the specific position/deposit ID, and a per-user monotonic nonce in the EIP-712 typed-data struct that is signed. Enforce `require(usedNonce[msg.sender][nonce] == false)` after verification. Prefer a salt + deadline so stale quotes expire."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.body_contains_regex': 'ecrecover\\s*\\(|ECDSA\\.recover|_verify\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_of_type': 'bytes'}, {'function.signature_regex': 'uint(\\d+)?|int(\\d+)?'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': 'ecrecover\\s*\\(|ECDSA\\.recover|_verify\\s*\\('}, {'function.body_not_contains_regex': 'keccak256\\s*\\(\\s*abi\\.encode[^)]*msg\\.sender|keccak256\\s*\\(\\s*abi\\.encode[^)]*(user|account|depositor|owner|to|recipient)'}, {'function.body_contains_regex': '(profit|payout|amount|reward|discount|price)\\s*=.*[-+*/]'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — signed-param-replay-across-users: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
