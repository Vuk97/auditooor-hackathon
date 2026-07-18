"""
abi-decode-user-bytes-no-length-check — generated from reference/patterns.dsl/abi-decode-user-bytes-no-length-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py abi-decode-user-bytes-no-length-check.yaml
Source: solodit/C0240
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AbiDecodeUserBytesNoLengthCheck(AbstractDetector):
    ARGUMENT = "abi-decode-user-bytes-no-length-check"
    HELP = "External/public function calls abi.decode on a caller-controlled bytes parameter without first validating the byte-length. Malformed calldata reverts inside the decoder (DoS on batched flows); in assembly variants the truncated buffer can corrupt memory."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/abi-decode-user-bytes-no-length-check.yaml"
    WIKI_TITLE = "abi.decode on user-supplied bytes without length pre-check"
    WIKI_DESCRIPTION = "The function accepts a bytes parameter from the caller and passes it directly to abi.decode (or abi.decodeWithSelector) without validating the blob's length. Solidity's decoder reverts on mis-sized input, turning a malformed payload into a guaranteed revert — a cheap DoS against any multicall, relayer, or hook dispatcher that batches this entry point. When the decode is performed in assembly, a tr"
    WIKI_EXPLOIT_SCENARIO = "A cross-chain message handler exposes `execute(bytes calldata payload) external` which immediately runs `(address to, uint256 amount, bytes memory data) = abi.decode(payload, (address, uint256, bytes));`. An attacker submits a 31-byte payload via the relayer. Decoding reverts, the outer batch reverts, and every honest message in the same batch is dropped. Repeating this each block costs the attack"
    WIKI_RECOMMENDATION = "Before abi.decode, assert the blob length matches the expected encoding: `require(payload.length >= MIN_LEN, 'short payload')` (for static struct types, MIN_LEN is 32 * field-count; dynamic types need additional per-field length verification). Where the decode sits inside a batch, wrap it in a try/c"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_of_type': 'bytes'}, {'function.body_contains_regex': 'abi\\.decode\\s*\\(|abi\\.decodeWithSelector\\s*\\('}, {'function.body_not_contains_regex': '\\.length\\s*(==|>=|>)\\s*\\d|require\\s*\\(.*\\.length|bytes\\.length\\s*>=?\\s*32'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — abi-decode-user-bytes-no-length-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
