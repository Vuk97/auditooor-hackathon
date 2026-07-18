"""
unsigned-feepips-allows-relayer-substitution — generated from reference/patterns.dsl/unsigned-feepips-allows-relayer-substitution.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py unsigned-feepips-allows-relayer-substitution.yaml
Source: solodit-novel/slice_ag
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UnsignedFeepipsAllowsRelayerSubstitution(AbstractDetector):
    ARGUMENT = "unsigned-feepips-allows-relayer-substitution"
    HELP = "EIP-712 struct hash excludes `feePips`/`relayerFee`. Relayer can swap in higher fee without invalidating the signature, skimming the delta from the signer."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/unsigned-feepips-allows-relayer-substitution.yaml"
    WIKI_TITLE = "EIP-712 payload excludes fee field; relayer substitutes higher fee"
    WIKI_DESCRIPTION = "Intent-based protocols where the relayer charges a fee must include the fee in the signed struct. Omitting `feePips`/`relayerFee` from the TYPEHASH means the fee is not part of the message hash, and any relayer submitting the same signature can insert their preferred fee (up to user balance), silently extracting value from the signer."
    WIKI_EXPLOIT_SCENARIO = "User signs `IntentMessage{to, token, amount}` to move 1000 USDC. Relayer submits the message with `feePips = 9000` (90%). The contract verifies the signature against the struct omitting feePips, the signature validates, and the relayer receives 900 USDC while the user receives 100. User expected a 10-pip fee (1 USDC)."
    WIKI_RECOMMENDATION = "Include every variable the user cares about in the TYPEHASH. For fees: `keccak256('IntentMessage(...,uint256 feePips)')`. Alternatively sign a `maxFeePips` and require `actualFee <= maxFeePips`."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'EIP712|_hashTypedDataV4|_domainSeparatorV4|typehash|TYPEHASH'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.has_param_name_matching': 'feePips|relayerFee|gasFee|bridgeFee|solverFee|executorFee'}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.body_contains_regex': '_hashTypedDataV4|keccak256\\s*\\(\\s*abi\\.encode\\s*\\(\\s*\\w+_TYPEHASH|ECDSA\\.recover'}, {'function.body_not_contains_regex': 'feePips\\s*,\\s*\\w+\\s*\\)|relayerFee\\s*,\\s*\\w+\\s*\\)|abi\\.encode\\s*\\([^)]*feePips'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — unsigned-feepips-allows-relayer-substitution: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
