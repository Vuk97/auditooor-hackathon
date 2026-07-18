"""
glider-return-bomb-bytes-capture — generated from reference/patterns.dsl/glider-return-bomb-bytes-capture.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-return-bomb-bytes-capture.yaml
Source: hexens-glider/classic-return-bomb-attack
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderReturnBombBytesCapture(AbstractDetector):
    ARGUMENT = "glider-return-bomb-bytes-capture"
    HELP = "Low-level `.call`/`.staticcall`/`.delegatecall` captures returndata into `bytes memory` without bounding the length. A malicious callee can return gigabytes of data to grief the caller's gas budget (return-bomb)."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-return-bomb-bytes-capture.yaml"
    WIKI_TITLE = "Return-bomb: unbounded `bytes memory` capture from low-level call"
    WIKI_DESCRIPTION = "`(bool ok, bytes memory ret) = target.call(data)` allocates memory to hold the full returndata. A hostile callee can return arbitrarily large data to force the caller to OOG. If the caller does not inspect `ret`, there is no reason to capture it — discard with `(bool ok, )` instead."
    WIKI_EXPLOIT_SCENARIO = "Aggregator iterates a user-supplied list of targets with `.call` and saves returndata for each in a `bytes[]`. One target returns `type(uint256).max` bytes — the caller OOGs before completing the loop, DoSing the batch path."
    WIKI_RECOMMENDATION = "If you don't need returndata, discard it: `(bool ok, ) = target.call(data);`. If you do, copy only the first N bytes via assembly: `let len := returndatasize(); if gt(len, CAP) { len := CAP } returndatacopy(ret, 0, len)`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\.call\\{|\\.call\\(|staticcall|delegatecall'}]
    _MATCH = [{'function.kind': 'any'}, {'function.has_low_level_call': True}, {'function.body_contains_regex': '\\(\\s*bool\\s+\\w+\\s*,\\s*bytes\\s+memory\\s+\\w+\\s*\\)\\s*=\\s*\\w+\\s*\\.(call|staticcall|delegatecall)|\\(\\s*,\\s*bytes\\s+memory\\s+\\w+\\s*\\)\\s*=\\s*\\w+\\s*\\.(call|staticcall|delegatecall)'}, {'function.body_not_contains_regex': 'returndatasize\\s*\\(\\s*\\)|ret\\.length\\s*<=|\\w+\\.length\\s*<\\s*MAX_RET|MAX_RETURN|cap\\s*=\\s*gasleft'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-return-bomb-bytes-capture: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
