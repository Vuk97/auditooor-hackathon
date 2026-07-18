"""
delegatecall-to-unvalidated-eoa — generated from reference/patterns.dsl/delegatecall-to-unvalidated-eoa.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py delegatecall-to-unvalidated-eoa.yaml
Source: auditooor-seed
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DelegatecallToUnvalidatedEoa(AbstractDetector):
    ARGUMENT = "delegatecall-to-unvalidated-eoa"
    HELP = "delegatecall target is not verified to be a contract — calling it when target is an EOA returns success=true with no code executed, silently corrupting state."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/delegatecall-to-unvalidated-eoa.yaml"
    WIKI_TITLE = "delegatecall to unvalidated EOA target"
    WIKI_DESCRIPTION = "A function performs `target.delegatecall(data)` without first asserting `target.code.length > 0` (or equivalent `Address.isContract` check). If `target` is an externally-owned account — either because a setter was called with a mistyped address, a factory returned address(0), or an adversarial input slipped through — the delegatecall is a no-op. The EVM returns `success = true` and empty return da"
    WIKI_EXPLOIT_SCENARIO = "A proxy's `upgradeToAndCall(address impl, bytes data)` stores `impl` and then `(bool ok, ) = impl.delegatecall(data)` to run the new implementation's initializer. The admin mistypes one hex digit, setting `impl` to an EOA. The delegatecall returns `success=true` with no code run, but the proxy now has the EOA as its implementation. All subsequent user calls to the proxy hit `fallback → delegatecal"
    WIKI_RECOMMENDATION = "Before any `delegatecall`, assert the target is a contract: `require(target.code.length > 0, 'target not a contract')` (or use OpenZeppelin `Address.isContract(target)`). Better still, constrain the target to an immutable / allow-listed implementation so an EOA can never be supplied."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.taints_param_to': {'from': '(?i)(impl|target|to|callee|module|logic|address|addr)', 'to': 'delegatecall', 'guard': 'require|isContract|code\\.length|extcodesize', 'depth': 3}}, {'function.body_contains_regex': '\\.delegatecall\\s*\\('}, {'function.body_not_contains_regex': '\\.code\\.length\\s*>\\s*0|Address\\.isContract|code\\.length\\s*!=\\s*0|require\\s*\\(.*code\\.length'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — delegatecall-to-unvalidated-eoa: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
