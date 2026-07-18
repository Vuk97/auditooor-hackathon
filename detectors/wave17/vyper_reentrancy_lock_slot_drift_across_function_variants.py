"""
vyper-reentrancy-lock-slot-drift-across-function-variants — generated from reference/patterns.dsl/vyper-reentrancy-lock-slot-drift-across-function-variants.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vyper-reentrancy-lock-slot-drift-across-function-variants.yaml
Source: auditooor-R76-rekt-curve-vyper-2023
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VyperReentrancyLockSlotDriftAcrossFunctionVariants(AbstractDetector):
    ARGUMENT = "vyper-reentrancy-lock-slot-drift-across-function-variants"
    HELP = "Vyper 0.2.15 / 0.2.16 / 0.3.0 allocate inconsistent storage slots to shared `@nonreentrant('lock')` decorators across multiple functions, breaking the reentrancy lock. Any Curve/stable-pool function that transfers native ETH can be reentered from the recipient's fallback."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vyper-reentrancy-lock-slot-drift-across-function-variants.yaml"
    WIKI_TITLE = "Vyper 0.2.15-0.3.0 @nonreentrant storage-slot drift breaks cross-function reentrancy lock"
    WIKI_DESCRIPTION = "Vyper compiler versions 0.2.15, 0.2.16, and 0.3.0 contain a compiler bug where the storage slot backing a shared `@nonreentrant('lock')` decorator is not consistently allocated across all functions that declare it. Functions intended to share the lock end up with different slots, so entering one does not block reentering another. In Curve pools that send native ETH (e.g. the alETH/ETH pool's `remo"
    WIKI_EXPLOIT_SCENARIO = "Pool compiled with Vyper 0.3.0. Attacker calls `remove_liquidity(lp_amount, min_amounts, true)` which sends ETH via `raw_call(recipient, b'', value=eth_amount)`. Recipient is attacker's contract. In the fallback, attacker calls `add_liquidity([huge_amount, 0], 0)`. Because the nonreentrant lock's slots do not match, the reentry passes. `add_liquidity` reads the current pool state (post-withdrawal "
    WIKI_RECOMMENDATION = "Upgrade the pool's Vyper pragma to 0.3.1 or later (the bug was patched — silently — in 0.3.1). Re-deploy affected pools. Monitor `pragma version` in contract metadata for 0.2.15/0.2.16/0.3.0 and flag any such contract that also transfers native ETH in an outer non-reentrant function. If upgrade is n"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, "Contract is compiled with Vyper 0.2.15, 0.2.16, or 0.3.0 (vulnerable compilers) AND exposes at least two functions decorated with `@nonreentrant('<same-name>')`."]
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)add_liquidity|remove_liquidity|exchange|claim_admin_fees|withdraw_admin_fees'}, {'function.body_contains_regex': '(?i)@nonreentrant|nonreentrant\\(|send\\s*\\(\\s*[^,]+,\\s*amount|raw_call.*value'}, {'function.body_not_contains_regex': '(?i)pragma\\s+vyper\\s+0\\.3\\.[1-9]|pragma\\s+vyper\\s+0\\.3\\.1[0-9]|pragma\\s+solidity|pragma\\s+version\\s+\\^0\\.3\\.(1|7|10)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — vyper-reentrancy-lock-slot-drift-across-function-variants: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
