"""
rebasing-allowance-drift-router-theft — generated from reference/patterns.dsl/rebasing-allowance-drift-router-theft.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rebasing-allowance-drift-router-theft.yaml
Source: auditooor-R75-c4-yield-2024-06-thorchain-85

Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY.
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RebasingAllowanceDriftRouterTheft(AbstractDetector):
    ARGUMENT = "rebasing-allowance-drift-router-theft"
    HELP = "Vault allowance tracked in nominal units on a whitelisted rebasing token (e.g. AMPL, stETH) — after a rebase, old allowance + new balance diverge allowing theft."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rebasing-allowance-drift-router-theft.yaml"
    WIKI_TITLE = "Rebasing token whitelisted on router with nominal-unit allowance accounting enables cross-user theft"
    WIKI_DESCRIPTION = "Cross-chain / bridge routers that hold per-vault allowances in nominal ERC20 units are broken by rebasing tokens whitelisted for deposit. Because the allowance is snapshot at deposit time but the underlying token balance changes on every rebase, a holder who deposited before a positive rebase ends up over-approved relative to the current balance. When a new depositor adds real balance after the re"
    WIKI_EXPLOIT_SCENARIO = "AMPL is on ThorChain's whitelist. Attacker deposits 1000 AMPL when gonsPerFragment=1, allowance = 1000. Rebase doubles gonsPerFragment → contract balance becomes 500, allowance still 1000. Legit user deposits 1000 AMPL post-rebase → contract balance = 1500. Attacker transfers out 1000 using old allowance, leaving victim only 500 of their 1000."
    WIKI_RECOMMENDATION = "Either (a) blacklist rebasing tokens from deposit paths that track nominal allowances, or (b) track allowances in rebase-invariant units (gons for AMPL, shares for stETH). On every deposit, compare received balance delta to requested amount and update allowance from the delta."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)contract\\s+\\w*(router|vault|bridge.*router|asgard|dispenser)\\w*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(deposit|transferAllowance|transferOut|routerDeposit)'}, {'function.writes_storage_matching': '(?i)(_vaultAllowance|vaultAllowance|allowance)'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': '(?i)(IERC20|token)\\.balanceOf\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.body_not_contains_regex': '(?i)(sharesOf|nonRebasingBalanceOf|getPooledEthByShares|_checkRebasing|rebaseMultiplier)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — rebasing-allowance-drift-router-theft: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
