"""
glider-unprotected-selfdestruct — generated from reference/patterns.dsl/glider-unprotected-selfdestruct.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-unprotected-selfdestruct.yaml
Source: hexens-glider/self-destructable-contracts
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderUnprotectedSelfdestruct(AbstractDetector):
    ARGUMENT = "glider-unprotected-selfdestruct"
    HELP = "`selfdestruct` called from a public/external function with no access control and no inline caller check. Any account can destroy the contract and redirect the balance to an attacker-supplied address. SWC-106."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-unprotected-selfdestruct.yaml"
    WIKI_TITLE = "Unprotected `selfdestruct` / `SELFDESTRUCT`"
    WIKI_DESCRIPTION = "The contract exposes a public or external function whose body ultimately invokes `selfdestruct(target)` with no caller validation. Any externally-owned account can permanently destroy the contract, redirect its ETH balance to any address, and invalidate every downstream integration that assumed it was live. Post-Cancun `SELFDESTRUCT` semantics changed — it no longer deletes code for pre-existing c"
    WIKI_EXPLOIT_SCENARIO = "Contract `Vault` exposes `function kill(address payable to) external { selfdestruct(to); }` with no modifier. Attacker calls `vault.kill(attacker)` and sweeps the contract's entire ETH balance. If `Vault` is the implementation of a proxy, every proxy pointing at it is now pointing at dead code — a total protocol bricking. This was the 2nd Parity multisig vulnerability."
    WIKI_RECOMMENDATION = "Remove `selfdestruct` entirely unless you have a concrete lifecycle reason to keep it. If you must keep it, gate with a multisig + timelock + pause precondition (e.g. `require(paused && msg.sender == timelock && block.timestamp > graceEnd)`). Never permit `selfdestruct` in the implementation of a pr"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'selfdestruct|suicide'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.body_contains_regex': 'selfdestruct\\s*\\(|suicide\\s*\\('}, {'function.has_modifier': {'includes': []}}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.sender|require\\s*\\(\\s*owner\\s*==|require\\s*\\(\\s*admin\\s*=='}, {'function.is_constructor': False}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-unprotected-selfdestruct: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
