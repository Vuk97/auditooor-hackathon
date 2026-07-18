"""
external-call-full-returndata-copy-to-memory — generated from reference/patterns.dsl/external-call-full-returndata-copy-to-memory.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py external-call-full-returndata-copy-to-memory.yaml
Source: auditooor-R71-fixdiff-mined-uniswap-v4-c0adc1c5
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ExternalCallFullReturndataCopyToMemory(AbstractDetector):
    ARGUMENT = "external-call-full-returndata-copy-to-memory"
    HELP = "Hook/callback dispatched with `target.call(data)` into a `bytes memory result` variable forces copy of full returndata. Attacker hook returning 2^20 bytes grieves gas."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/external-call-full-returndata-copy-to-memory.yaml"
    WIKI_TITLE = "Hook dispatched via solidity call copies full returndata — return-bomb gas grief"
    WIKI_DESCRIPTION = "`(bool ok, bytes memory result) = target.call(data)` eagerly copies the callee's entire returndata into Solidity-managed memory, regardless of whether the caller will read it. A malicious hook can return megabytes of data to exhaust the caller's gas. Production AMMs should either (a) drop returndata entirely via `call(gas, target, 0, in, inlen, 0, 0)` and `returndatacopy` only the bytes they actua"
    WIKI_EXPLOIT_SCENARIO = "Uniswap v4 PR #705 (2024): a hook with BEFORE_SWAP_FLAG returned 0x100000 bytes of padding. The pool manager's `target.call(data)` path copied it all, making every swap against that pool cost ~3M extra gas and effectively bricking the pool for normal users while letting the hook author grief arbitrage competitors."
    WIKI_RECOMMENDATION = "Use inline assembly: `success := call(gas(), hook, 0, add(data, 0x20), mload(data), 0, 0)` — writes no returndata to memory. Then conditionally `returndatacopy` only after verifying expected size (e.g. `if (returndatasize() > MAX_RETURN) revert ReturnBomb()`), or use ERC-7751 wrapped revert bubbling"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': 'callHook|_call|invokeCallback|externalCall'}, {'function.body_contains_regex': '\\(\\s*bool\\s+\\w+\\s*,\\s*bytes\\s+memory\\s+\\w+\\s*\\)\\s*=\\s*\\w+\\.call\\s*\\('}, {'function.body_contains_regex': 'address\\s*\\(\\s*self\\s*\\)\\.call|address\\s*\\(\\s*hook\\s*\\)\\.call|IHooks|ICallback'}, {'function.body_not_contains_regex': 'returndatasize\\s*\\(\\s*\\)\\s*(<|<=|>)|call\\s*\\(\\s*gas\\s*\\(\\s*\\)\\s*,[^)]+\\,\\s*0\\s*,\\s*0\\s*\\)|bubble'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — external-call-full-returndata-copy-to-memory: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
