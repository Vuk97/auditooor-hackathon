"""
aggregate-router-wrap-eth-no-msgvalue-check-drains-contract-eth — generated from reference/patterns.dsl/aggregate-router-wrap-eth-no-msgvalue-check-drains-contract-eth.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py aggregate-router-wrap-eth-no-msgvalue-check-drains-contract-eth.yaml
Source: auditooor-R75-c4-mined-2024-10-ronin-8
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AggregateRouterWrapEthNoMsgvalueCheckDrainsContractEth(AbstractDetector):
    ARGUMENT = "aggregate-router-wrap-eth-no-msgvalue-check-drains-contract-eth"
    HELP = "Universal/Aggregate router's WRAP_ETH command wraps `amount = address(this).balance` (or user-supplied amount up to balance) without verifying the caller actually sent `msg.value >= amount`. If the router contract has a nonzero ETH balance at any point (stuck dust, refund from prior tx, admin mistak"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/aggregate-router-wrap-eth-no-msgvalue-check-drains-contract-eth.yaml"
    WIKI_TITLE = "AggregateRouter WRAP_ETH command allows anyone to wrap contract's ETH to attacker's WETH"
    WIKI_DESCRIPTION = "AggregateRouter.execute processes a list of Commands. For Commands.WRAP_ETH, Dispatcher decodes (recipient, amountMin) from inputs and calls `Payments.wrapETH(recipient, amountMin)`. wrapETH: `if (amount == CONTRACT_BALANCE) amount = this.balance; else if (amount > this.balance) revert; WETH9.deposit{value: amount}(); WETH9.transfer(recipient, amount);`. Nowhere does execute validate that the call"
    WIKI_EXPLOIT_SCENARIO = "Due to a failed compound operation earlier, AggregateRouter holds 5 ETH as dust. Attacker crafts `commands = [WRAP_ETH]`, `inputs = [abi.encode(attacker, CONTRACT_BALANCE)]`. Calls `router.execute{value: 0}(commands, inputs, deadline)`. Dispatcher processes WRAP_ETH: amount = address(this).balance = 5 ETH. WETH9.deposit{value: 5 ETH}() → WETH mint to router. WETH9.transfer(attacker, 5 ETH). Attack"
    WIKI_RECOMMENDATION = "Each command that transfers ETH out of the router (WRAP_ETH, TRANSFER with ETH) must credit it only from the user's msg.value accounting. Maintain a per-call `remainingMsgValue` counter initialized to `msg.value`, decrement on each ETH-consuming command, and revert if balance-based transfer is attem"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'AggregateRouter|Dispatcher|UniversalRouter|Commands'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '^(dispatch|_dispatch|execute|_execute)$'}, {'function.body_contains_regex': 'WRAP_ETH|wrapETH|WETH9\\.deposit'}, {'function.body_contains_regex': 'Constants\\.CONTRACT_BALANCE|address\\(this\\)\\.balance|this\\.balance'}, {'function.body_not_contains_regex': '(msg\\.value\\s*>=\\s*amount|msg\\.value\\s*==\\s*amount|require\\s*\\(\\s*msg\\.value\\s*[<>!=]|_checkMsgValue)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — aggregate-router-wrap-eth-no-msgvalue-check-drains-contract-eth: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
