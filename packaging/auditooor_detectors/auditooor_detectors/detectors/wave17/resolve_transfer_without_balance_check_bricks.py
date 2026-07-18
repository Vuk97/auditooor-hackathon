"""
resolve-transfer-without-balance-check-bricks — generated from reference/patterns.dsl/resolve-transfer-without-balance-check-bricks.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py resolve-transfer-without-balance-check-bricks.yaml
Source: polymarket-draft-3
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ResolveTransferWithoutBalanceCheckBricks(AbstractDetector):
    ARGUMENT = "resolve-transfer-without-balance-check-bricks"
    HELP = "External resolve/_resolve/finalize/close/settle/distribute function performs ERC20 transfer without a prior balance/zero-amount guard — zero balance reverts the call, bricking on-chain resolution (Polymarket Draft 3)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/resolve-transfer-without-balance-check-bricks.yaml"
    WIKI_TITLE = "Resolve / settle path performs ERC20 transfer without balance check, bricks on zero balance"
    WIKI_DESCRIPTION = "An external resolution entrypoint (resolve/_resolve/finalize/close/settle/distribute) on an adapter/oracle/market contract calls IERC20.transfer or SafeERC20.safeTransfer without first checking the contract's balance or short-circuiting on zero. If a prior code path (dispute callback, refund, partial settlement) has already consumed the contract's balance, the transfer reverts. Because the resolve"
    WIKI_EXPLOIT_SCENARIO = "Polymarket UmaCtfAdapter._resolve (src/v1/uma/UmaCtfAdapter.sol:416) handles the OO's int256.min ignore sentinel by calling _reset(address(this), ...) which in turn opens a fresh OO request via _requestPrice. The OO's transferFrom(adapter, oo, reward) fails when the adapter balance is 0 (because a prior priceDisputed callback already consumed the refund into the new request). The entire resolve() "
    WIKI_RECOMMENDATION = "Before any transfer / safeTransfer on a resolution path, gate on the contract's balance: `uint256 bal = IERC20(rewardToken).balanceOf(address(this)); if (bal < questionData.reward) { questionData.paused = true; emit ResolutionRequiresManualIntervention(questionID); return; }`. Or short-circuit on ze"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(adapter|oracle|uma|resolve|market)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(resolve|_resolve|finalize|close|settle|distribute)'}, {'function.body_contains_regex': '\\.(?:safeTransfer|transfer)\\s*\\('}, {'function.body_not_contains_regex': '(balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|if\\s*\\(\\s*\\w+\\s*==\\s*0\\s*\\)|require\\s*\\(\\s*\\w+(\\.\\w+)?\\s*>\\s*0|\\w+\\s*==\\s*0\\s*\\)\\s*return)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — resolve-transfer-without-balance-check-bricks: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
