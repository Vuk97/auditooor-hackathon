"""
r74-error-assumption-on-unsuccessful-call-output — generated from reference/patterns.dsl/r74-error-assumption-on-unsuccessful-call-output.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-error-assumption-on-unsuccessful-call-output.yaml
Source: r74b-cross-firm-cs+oz
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74ErrorAssumptionOnUnsuccessfulCallOutput(AbstractDetector):
    ARGUMENT = "r74-error-assumption-on-unsuccessful-call-output"
    HELP = "Low-level `.call` revert handling decodes returndata assuming only `Error(string)` / `Panic(uint256)` selectors, so custom errors are misclassified or collapsed into a generic fallback."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-error-assumption-on-unsuccessful-call-output.yaml"
    WIKI_TITLE = "Unsuccessful-call returndata decoded without custom-error fallback"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row proves only the owned shape where a low-level `.call` captures `bytes memory returndata`, branches on `!success`, and classifies the revert by matching built-in selectors such as `0x08c379a0` and `0x4e487b71`. Custom errors have arbitrary selectors, so a decoder that handles only `Error(string)` / `Panic(uint256)` can silently downg"
    WIKI_EXPLOIT_SCENARIO = "A relay catches a failed low-level call and tries to surface a user-friendly reason by decoding only `Error(string)` and `Panic(uint256)`. The target instead reverts with `error Unauthorized(address caller)`. The relay falls through to an `unknown revert` branch that suppresses the underlying revert semantics and retries or misreports the failure, opening a denial-of-service or policy-bypass path."
    WIKI_RECOMMENDATION = "On `!success`, bubble the raw returndata whenever possible: `assembly { revert(add(returndata, 32), mload(returndata)) }`. If classification is required, still preserve an opaque custom-error fallback instead of assuming only the built-in selectors."

    _PRECONDITIONS = []
    _MATCH = [{'function.kind': 'any'}, {'function.has_low_level_call': {'op': 'call'}}, {'function.body_contains_regex': '\\(\\s*bool\\s+\\w+\\s*,\\s*bytes\\s+memory\\s+(returndata|returnData|_returndata|\\w*return\\w*)\\s*\\)\\s*=\\s*\\w+\\.call\\s*(\\{|\\()'}, {'function.body_contains_regex': 'if\\s*\\(\\s*!\\s*(success|ok)\\s*\\)|if\\s*\\(\\s*(success|ok)\\s*==\\s*false\\s*\\)'}, {'function.body_contains_regex': '0x08c379a0|0x4e487b71|Error\\s*\\(\\s*string\\s*\\)|Panic\\s*\\(\\s*uint'}, {'function.body_contains_regex': 'abi\\.decode\\s*\\('}, {'function.body_not_contains_regex': 'assembly\\s*\\{[^}]*revert\\s*\\(\\s*add\\s*\\(\\s*(returndata|returnData|_returndata|\\w*return\\w*)\\s*,\\s*32\\s*\\)\\s*,\\s*mload\\s*\\(\\s*(returndata|returnData|_returndata|\\w*return\\w*)\\s*\\)\\s*\\)|Address\\.verifyCallResult|verifyCallResultFromTarget|_revertWithReturndata|_bubbleRevert'}, {'function.body_not_contains_regex': '\\w+\\.selector\\s*==\\s*selector|selector\\s*==\\s*\\w+\\.selector|bytes4\\s*\\(\\s*(returndata|returnData|_returndata|\\w*return\\w*)\\s*\\[\\s*:?\\s*4\\s*\\]?\\s*\\)\\s*==\\s*\\w+\\.selector'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-error-assumption-on-unsuccessful-call-output: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
