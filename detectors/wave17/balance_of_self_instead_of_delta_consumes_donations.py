"""
balance-of-self-instead-of-delta-consumes-donations — generated from reference/patterns.dsl/balance-of-self-instead-of-delta-consumes-donations.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py balance-of-self-instead-of-delta-consumes-donations.yaml
Source: auditooor-R77-polymarket-adapters-redeemPositions
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BalanceOfSelfInsteadOfDeltaConsumesDonations(AbstractDetector):
    ARGUMENT = "balance-of-self-instead-of-delta-consumes-donations"
    HELP = "Function uses `token.balanceOf(address(this))` as the payout amount instead of a pre/post delta. Any prior-stuck balance is consumed by the next caller."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/balance-of-self-instead-of-delta-consumes-donations.yaml"
    WIKI_TITLE = "balanceOf(self) used instead of delta — donation / stuck-fund skim"
    WIKI_DESCRIPTION = "A function performs an operation that increases the contract's token balance (e.g., CTF redeemPositions returns collateral), then reads `token.balanceOf(address(this))` and pays ALL of it to the caller. Any balance that was ALREADY sitting in the contract (from a prior donation, stuck dust, or operational mistake) is harvested by the next caller — a 'donation skim' pattern."
    WIKI_EXPLOIT_SCENARIO = "Protocol deploys adapter X with a redeem function that reads `token.balanceOf(X)` to determine payout. User Alice accidentally sends 10,000 USDC to X. Attacker Bob immediately submits redeem with a valid 1-wei position, receiving his own redemption + Alice's 10,000 USDC (wrapped as pUSD). Alice's funds are permanently lost to Bob."
    WIKI_RECOMMENDATION = "Use pre/post balance delta instead of raw balanceOf:\n```\nuint256 before = token.balanceOf(address(this));\n_redeemPositions(...);\nuint256 amount = token.balanceOf(address(this)) - before;\n```\nAdd a separate admin `sweepStale(address asset)` to recover donations."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)redeem|mergePositions|convertPositions|claim|withdraw'}, {'function.body_contains_regex': '(?i)\\.balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)'}, {'function.body_not_contains_regex': '(?i)balanceBefore|bal[_]?before|\\w*[Bb]alance[A-Z]?[Bb]efore\\s*=\\s*\\w+\\.balanceOf'}, {'function.has_high_level_call_named': '(?i)redeem|merge|wrap|unwrap|transfer'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — balance-of-self-instead-of-delta-consumes-donations: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
