"""
first-deposit-totalsupply-zero-oracle-init — generated from reference/patterns.dsl/first-deposit-totalsupply-zero-oracle-init.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py first-deposit-totalsupply-zero-oracle-init.yaml
Source: solodit-novel/slice_aa
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FirstDepositTotalsupplyZeroOracleInit(AbstractDetector):
    ARGUMENT = "first-deposit-totalsupply-zero-oracle-init"
    HELP = "Vault first-deposit mints shares from oracle price. Attacker 1-wei donation manipulates share price so subsequent deposits round to 0 shares."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/first-deposit-totalsupply-zero-oracle-init.yaml"
    WIKI_TITLE = "First-deposit donation attack on oracle-initialized share price"
    WIKI_DESCRIPTION = "Vaults that initialize share price from an oracle (rather than 1:1 at first deposit) expose a donation front-run. Attacker donates 1 wei of asset to the vault before anyone deposits. The oracle-driven share calculation divides by very small `totalSupply`, producing a huge effective share price. User `deposit(1000e18)` now mints 0 shares after integer truncation; the 1000e18 is effectively a gift t"
    WIKI_EXPLOIT_SCENARIO = "glif-12 finding. Vault `convertToShares(assets) = assets * oraclePrice() / sharePrice()` where sharePrice = totalAssets() * 1e18 / totalSupply. Attacker deposits the first share (1 wei). Then directly transfers 1e18 asset to vault. sharePrice is now ~1e18 / 1 = 1e18 per wei of share. Any user depositing less than sharePrice worth of assets mints 0 shares and loses their deposit entirely to the att"
    WIKI_RECOMMENDATION = "Seed the vault with dead-shares on deploy (`_mint(address(0), 1e6)`), or require minimum initial deposit (`MIN_INITIAL_DEPOSIT = 1e6`). Revert on `shares == 0`. For oracle-initialized vaults, explicitly bound first deposit to a fixed 1:1 ratio and disable oracle-based calculation until totalSupply >"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'previewDeposit|convertToShares|oraclePrice|initialSharePrice'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': 'deposit|initialize|_init|firstDeposit|seed'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': 'totalSupply\\s*\\(\\s*\\)|_totalSupply|\\btotalSupply\\b'}, {'function.body_contains_regex': 'oracle|getPrice|latestAnswer|sharePrice|exchangeRate'}, {'function.body_not_contains_regex': 'MIN_INITIAL|seedAmount|BOOTSTRAP|_mint\\s*\\(\\s*address\\s*\\(\\s*0|require\\s*\\(\\s*shares\\s*>\\s*0|require\\s*\\(\\s*_totalSupply\\s*>'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — first-deposit-totalsupply-zero-oracle-init: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
