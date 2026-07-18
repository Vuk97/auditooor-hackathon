"""
dh-lending-donate-inflates-exchange-rate — generated from reference/patterns.dsl/dh-lending-donate-inflates-exchange-rate.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dh-lending-donate-inflates-exchange-rate.yaml
Source: defihacklabs-2026-03/Venus_THE
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DhLendingDonateInflatesExchangeRate(AbstractDetector):
    ARGUMENT = "dh-lending-donate-inflates-exchange-rate"
    HELP = "Lending market exchange-rate formula depends on token.balanceOf(address(this)) instead of an internally-tracked `totalCash`. Any external transfer() donates cash into the pool and inflates the rate — used to over-collateralize positions or print undeserved collateral value."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dh-lending-donate-inflates-exchange-rate.yaml"
    WIKI_TITLE = "Exchange rate uses live balanceOf — donation-manipulable"
    WIKI_DESCRIPTION = "Compound-fork lending markets (cToken, vToken) compute exchangeRate = (cash + borrows - reserves) / totalSupply, where cash is often implemented as ERC20.balanceOf(address(this)). This means an attacker can transfer tokens DIRECTLY to the market (outside the mint flow) to inflate cash and therefore exchangeRate, which distorts collateral valuations and borrow limits."
    WIKI_EXPLOIT_SCENARIO = "Venus_THE (Mar 2026): attacker steals THE tokens from pre-approvals and donates them to vTHE. cash(vTHE) jumps, inflating vTHE exchange rate and the collateral USD value of a victim account that already held vTHE. Attacker then uses borrowBehalf on the victim to extract USDC/CAKE/WBNB."
    WIKI_RECOMMENDATION = "Track cash internally: increment on mint / redeem / borrow / repay and never read balanceOf. Any excess tokens received outside the accounted flow are swept to governance, not credited to the market."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(CToken|VToken|CErc20|CEther|CompoundFork|Compound|Venus|MoneyMarket|Comptroller|exchangeRateStored|exchangeRateCurrent|getCash|cToken|vToken|CompTroller)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(exchangeRateStored|exchangeRateCurrent|exchangeRate|getCash|cash|_getCash|getCashPrior|_exchangeRate)$'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)'}, {'function.body_not_contains_regex': 'internalBalance|_cash\\b|accountedCash'}, {'function.not_source_matches_regex': '(MockERC20|MockToken|TestToken|super\\.exchangeRate|super\\.getCash|totalReserves\\s*\\+|cashPrior\\s*=\\s*\\w*Internal|view\\s+returns\\s*\\(\\s*uint256\\s*\\)\\s*\\{\\s*return\\s+_cash)'}]

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
                info = [f, f" — dh-lending-donate-inflates-exchange-rate: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
