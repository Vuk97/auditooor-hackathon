"""
erc20-wrapper-deposit-for-allows-wrapper-as-recipient — generated from reference/patterns.dsl/erc20-wrapper-deposit-for-allows-wrapper-as-recipient.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc20-wrapper-deposit-for-allows-wrapper-as-recipient.yaml
Source: lisa-mine-r99-case-00922-cantina-aleph-zero-psp22-2024
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc20WrapperDepositForAllowsWrapperAsRecipient(AbstractDetector):
    ARGUMENT = "erc20-wrapper-deposit-for-allows-wrapper-as-recipient"
    HELP = "ERC-20 / PSP22 token-wrapper exposes `depositFor(account, amount)` (and the symmetric `withdrawTo(account, ...)` / `wrap(to, ...)`) WITHOUT validating that `account != address(this)`. A user who calls `depositFor(wrapper, amount)` transfers their underlying into the wrapper, the wrapper mints wrappe"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc20-wrapper-deposit-for-allows-wrapper-as-recipient.yaml"
    WIKI_TITLE = "ERC-20 wrapper depositFor / wrapTo accepts wrapper itself as recipient"
    WIKI_DESCRIPTION = "Pattern fires on token-wrapper `depositFor` / `wrap` / `deposit_for` external entry points that take `(address account, uint256 amount)` and immediately mint wrapped tokens to `account`. Without `require(account != address(this), 'cannot wrap to self');`, a user can call `depositFor(wrapperAddress, amount)`. The wrapper pulls the underlying via `transferFrom`, mints `amount` wrapped tokens to its "
    WIKI_EXPLOIT_SCENARIO = "A user accidentally types the wrapper's address into a frontend's recipient field and calls `depositFor(0xWrapper, 100e18)`. The 100 underlying are pulled in, 100 wrapped tokens are minted to the wrapper. The user has no claim, the wrapper has no withdrawal path for its own balance. If this happens to a high-volume integrator (e.g. a custodian batch script), millions of dollars can sit stuck. Also"
    WIKI_RECOMMENDATION = "In every wrapper entry point that takes a recipient address, require `account != address(this)`: `require(account != address(this), 'WRAP_TO_SELF');`. The same check belongs in `withdrawTo` (`recipient != address(this)`) so the wrapper cannot transfer its own underlying. Keep a corresponding admin-c"

    _PRECONDITIONS = [{'contract.has_function_matching': 'depositFor|deposit_for|withdrawTo|withdraw_to|wrap|wrapFor'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(depositFor|deposit_for|wrap|wrapFor|wrapTo)$'}, {'function.body_contains_regex': '\\b(account|recipient|to)\\s*[,)]'}, {'function.body_not_contains_regex': '\\b(account|recipient|to)\\s*!=\\s*address\\s*\\(\\s*this\\s*\\)|require\\s*\\([^)]*self\\b|require\\s*\\([^)]*[Ww]rapper\\s*!=|require\\s*\\(\\s*to\\s*!=\\s*address\\s*\\(\\s*this'}, {'function.has_param_of_type': 'address'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — erc20-wrapper-deposit-for-allows-wrapper-as-recipient: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
