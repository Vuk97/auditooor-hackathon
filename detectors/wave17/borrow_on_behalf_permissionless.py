"""
borrow-on-behalf-permissionless — generated from reference/patterns.dsl/borrow-on-behalf-permissionless.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py borrow-on-behalf-permissionless.yaml
Source: defihacklabs/Venus_THE_2026-03
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BorrowOnBehalfPermissionless(AbstractDetector):
    ARGUMENT = "borrow-on-behalf-permissionless"
    HELP = "A borrow-on-behalf entry point lets any caller mint debt onto a third-party borrower's account without a delegation / allowance check. Combined with attacker-supplied donations that temporarily inflate the victim's collateral, the attacker drains cash against the victim's position (Venus vTHE borrow"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/borrow-on-behalf-permissionless.yaml"
    WIKI_TITLE = "Permissionless borrow-on-behalf: caller opens debt on third-party account"
    WIKI_DESCRIPTION = "A Compound/Venus-style fork exposes `borrowBehalf(borrower, amount)` that opens debt on `borrower`'s account but sends the borrowed cash to `msg.sender`. Without a delegation check (Aave-style `borrowAllowance[borrower][msg.sender]`, Compound-fork `borrowApproved`, or plain `msg.sender == borrower`), any caller can spend the victim's collateral value. When combined with an inflated collateral-valu"
    WIKI_EXPLOIT_SCENARIO = "Venus vTHE exposes `borrowBehalf(address borrower, uint256 borrowAmount)` with no allowance check. Attacker drains THENA from six EOAs that had pre-approved the attacker-contract address, donates that THENA directly into vTHE (inflating its exchange rate and the victim's collateral value via vTHE held by the victim), then calls `vUSDC.borrowBehalf(victim, 1.58M USDC)` — the USDC is sent to the att"
    WIKI_RECOMMENDATION = "Require an explicit delegation record before letting a third-party call open debt: Aave-style `borrowAllowance[borrower][msg.sender] >= amount` with decrement on borrow, Compound-fork `_borrowApproved(borrower, msg.sender)`, or the simpler `require(msg.sender == borrower, \"no delegation\")`. Do not"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'borrow|debt|accountBorrows|borrowBalance'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(borrow(On)?Behalf|borrowFor|creditAccountBorrow)$'}, {'function.has_param_name_matching': '(?i)(borrower|onBehalfOf|account|debtor|user)'}, {'function.writes_storage_matching': 'borrow|debt|accountBorrows'}, {'function.body_not_contains_regex': '(_borrowAllowance|borrowAllowance|isApprovedForBorrow|borrowApproved|isAuthorized|delegatedBorrow|msg\\.sender\\s*==\\s*(borrower|onBehalfOf|account|user)|allowance\\s*\\[\\s*(borrower|onBehalfOf|account)\\s*\\]\\s*\\[\\s*msg\\.sender\\s*\\])'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — borrow-on-behalf-permissionless: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
