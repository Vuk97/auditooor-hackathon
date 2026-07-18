"""
borrow-transfers-native-before-debt-write-crossfn-reentrancy-exitmarket — generated from reference/patterns.dsl/borrow-transfers-native-before-debt-write-crossfn-reentrancy-exitmarket.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py borrow-transfers-native-before-debt-write-crossfn-reentrancy-exitmarket.yaml
Source: auditooor-R76-rekt-fei-rari-2022
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BorrowTransfersNativeBeforeDebtWriteCrossfnReentrancyExitmarket(AbstractDetector):
    ARGUMENT = "borrow-transfers-native-before-debt-write-crossfn-reentrancy-exitmarket"
    HELP = "borrow() sends ETH to the caller before writing the updated `borrowBalance`, letting a reentrant call into `Comptroller.exitMarket` see debt=0 and unmark the caller's collateral. Classic CEI violation across a cross-module boundary."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/borrow-transfers-native-before-debt-write-crossfn-reentrancy-exitmarket.yaml"
    WIKI_TITLE = "Borrow transfers native token to caller before persisting debt state, enabling exitMarket reentrancy"
    WIKI_DESCRIPTION = "In Compound/Rari-style fork lending markets, CEther.borrow forwards ETH to the borrower via a low-level call before writing `accountBorrows[borrower].principal`. If that same borrower has also supplied collateral and is in the market, their fallback can re-enter the Comptroller to call `exitMarket(cEther)`. Since the debt write has not happened yet, `getHypotheticalAccountLiquidity` sees `borrowBa"
    WIKI_EXPLOIT_SCENARIO = "Attacker deposits 150M USDC as collateral in Fuse pool 8. Calls `CEther.borrow(1977 ether)`. CEther does `msg.sender.call{value: 1977 ether}('')`. Attacker fallback calls `Comptroller.exitMarket(cEther)` — passes because borrowBalance is still 0. Fallback then calls `cUSDC.redeem(150M)` — passes because the 150M USDC is no longer locked as collateral. Fallback returns. CEther finally writes borrow"
    WIKI_RECOMMENDATION = "Apply strict checks-effects-interactions: write the new `accountBorrows` entry BEFORE the `call{value:}` that transfers ETH. Alternatively, add a reentrancy guard that is shared with the Comptroller (NOT just local to CEther), so reentrant `exitMarket` reverts. Audit every `.call{value:}` / `.call.v"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, "Lending contract's borrow() or redeem() path transfers native ETH to the user before persisting the debt / share-balance mutation."]
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)^borrow\\w*|^redeem\\w*|^withdraw\\w*|seizeInternal'}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.body_contains_regex': '(?i)\\.call\\s*\\{\\s*value\\s*:|\\.call\\.value\\s*\\(|sendValue|transfer\\s*\\(\\s*payable'}, {'function.body_not_contains_regex': '(?i)accountBorrows\\s*\\[[^\\]]+\\]\\s*=[\\s\\S]+\\.call|borrowBalanceStored\\s*=[\\s\\S]+\\.call|borrow(Balance|Amount)\\s*\\[[^\\]]+\\]\\s*=\\s*\\w+\\s*;[\\s\\S]*\\.call'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — borrow-transfers-native-before-debt-write-crossfn-reentrancy-exitmarket: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
