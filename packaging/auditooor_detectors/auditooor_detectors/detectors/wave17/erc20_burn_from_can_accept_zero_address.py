"""
erc20-burn-from-can-accept-zero-address — generated from reference/patterns.dsl/erc20-burn-from-can-accept-zero-address.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc20-burn-from-can-accept-zero-address.yaml
Source: auditooor-round-34
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc20BurnFromCanAcceptZeroAddress(AbstractDetector):
    ARGUMENT = "erc20-burn-from-can-accept-zero-address"
    HELP = "burn/burnFrom/_burn accepts an address parameter and writes balance/totalSupply without a zero-address guard; allows zero-address accounting corruption or forced reverts in batched paths."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc20-burn-from-can-accept-zero-address.yaml"
    WIKI_TITLE = "ERC20 burnFrom accepts address(0), corrupts accounting or grief-reverts"
    WIKI_DESCRIPTION = "The burn-family function (`burn`, `burnFrom`, `_burn`) takes an `address account` parameter and writes to `balance[account]` / `balances[account]` / `totalSupply` with no `require(account != address(0))` check. On modern compilers the call reverts on underflow when `balances[address(0)]` is zero — but that revert is itself a griefing vector in any batched code path that includes the burn. On older"
    WIKI_EXPLOIT_SCENARIO = "A bridge contract calls `token.burnFrom(user, amount)` in a loop. A malicious user registers `address(0)` as their withdrawal address. On a token implementation that uses `unchecked` around the balance decrement (common pre-0.8 ports), `balances[address(0)]` becomes `type(uint256).max - amount + 1` while `totalSupply` is decremented normally. The invariant `sum(balances) == totalSupply` is broken;"
    WIKI_RECOMMENDATION = "Add an explicit zero-address guard at the top of every burn-family entry point: `require(account != address(0), \"ERC20: burn from zero address\")` — matching OpenZeppelin's ERC20._burn. For custom errors: `if (account == address(0)) revert ZeroAddress();`. Also ensure the same guard exists in any p"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '_burn|burn|burnFrom'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(burn|burnFrom|_burn)$'}, {'function.has_param_of_type': 'address'}, {'function.writes_storage_matching': 'balance|balances|totalSupply'}, {'function.body_not_contains_regex': 'require\\s*\\(.*!=\\s*address\\s*\\(\\s*0|if\\s*\\(.*==\\s*address\\s*\\(\\s*0\\s*\\)\\s*revert|ZeroAddress\\s*\\(|_notZero'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc20-burn-from-can-accept-zero-address: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
