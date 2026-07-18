"""
ec-donation-inflates-share-price — generated from reference/patterns.dsl/ec-donation-inflates-share-price.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-donation-inflates-share-price.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcDonationInflatesSharePrice(AbstractDetector):
    ARGUMENT = "ec-donation-inflates-share-price"
    HELP = "totalAssets() returns raw balanceOf(address(this)); direct token donations bypass deposit accounting and inflate share price."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-donation-inflates-share-price.yaml"
    WIKI_TITLE = "totalAssets() uses raw balanceOf — donation attack inflates share price"
    WIKI_DESCRIPTION = "The vault's totalAssets() implementation returns token.balanceOf(address(this)), which reflects any token balance including direct transfers that bypass deposit(). An attacker can artificially inflate totalAssets by sending tokens to the vault address without minting proportional shares, making each existing share worth more — and all future depositors receive fewer shares than they should."
    WIKI_EXPLOIT_SCENARIO = "Attacker holds 1% of vault shares. Donates 100x the vault's current assets directly to vault address. totalAssets() jumps 100x. Attacker redeems 1% of shares for 1% of (100x assets) = almost the entire vault balance. All other depositors are diluted."
    WIKI_RECOMMENDATION = "Track totalAssets in an internal storage variable that only increases via deposit() and decreases via withdraw(). In totalAssets(), return the storage variable plus any yield (e.g., interest from a lending protocol) — not raw balanceOf(). This is the pattern used by OpenZeppelin's OZ4626 implementat"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'totalAssets|balanceOf.*address.*this'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^totalAssets$'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)'}, {'function.body_not_contains_regex': '_totalAssets\\b|internalBalance|storedAssets|_balance\\b|totalDeposited|trackedAssets|accountedAssets|cachedAssets|donationBuffer'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-donation-inflates-share-price: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
