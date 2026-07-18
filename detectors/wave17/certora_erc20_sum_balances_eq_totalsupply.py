"""
certora-erc20-sum-balances-eq-totalsupply — generated from reference/patterns.dsl/certora-erc20-sum-balances-eq-totalsupply.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-erc20-sum-balances-eq-totalsupply.yaml
Source: certora-examples/ERC20/sumOfBalancesEqualsTotalSupply
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraErc20SumBalancesEqTotalsupply(AbstractDetector):
    ARGUMENT = "certora-erc20-sum-balances-eq-totalsupply"
    HELP = "Balance writer mutates per-user balance without updating totalSupply — violates Certora's `sumOfBalancesEqualsTotalSupply` invariant."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-erc20-sum-balances-eq-totalsupply.yaml"
    WIKI_TITLE = "Balance mutation without totalSupply update (sum(balances) != totalSupply)"
    WIKI_DESCRIPTION = "Certora's canonical ERC20/ERC4626 spec proves `sum(balanceOf(u) for all u) == totalSupply()`. A function that rewrites `_balances[x]` (mint-like, burn-like, seize, redeem, internal migration) without mirroring the change into `totalSupply` will break the invariant. Consumers that read totalSupply (maxSupply caps, reward-per-share, vault price-per-share) diverge silently from the true circulating q"
    WIKI_EXPLOIT_SCENARIO = "A custom `seize(borrower, liquidator, amount)` moves cToken-style collateral from borrower to liquidator by writing `_balances[borrower] -= amount; _balances[liquidator] += amount;` — mass-conserving for transfer. But a sibling `_migrateOut(user)` zeroes `_balances[user]` during a migration event without touching totalSupply. After migration, `sum(balances) < totalSupply`, and the next deposit hit"
    WIKI_RECOMMENDATION = "Every balance write must be paired with the corresponding totalSupply delta. Prefer centralizing all balance mutation through `_update(from, to, amount)` so pure transfers leave totalSupply untouched, and only mint/burn branches modify it. Assert the Certora invariant as a Foundry fuzz test."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(ERC20|ERC4626|IERC20|_balances|balanceOf|totalSupply|shareOf|sharesOf|_mint|_burn)'}, {'contract.has_state_var_matching': '(?i)(totalSupply|_totalSupply|totalShares|totalLocked|totalAssets)'}, {'contract.has_state_var_matching': '(?i)(_balances|balances|shareOf|sharesOf|balanceOf)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.is_mutating': True}, {'function.writes_storage_matching': '(?i)(_balances|balances|shareOf|sharesOf)'}, {'function.body_not_contains_regex': '(?i)(totalSupply|_totalSupply|totalShares|totalLocked|totalAssets)\\s*(\\+=|-=|=.*[+\\-])'}, {'function.name_matches': '(?i)^(mint|burn|_mint|_burn|_update|_transfer|_move|_rebalance|seize|_seize|redeem|_redeem|_deposit|credit|_credit|debit|_debit|migrate|_migrateOut|_migrateIn)\\w*$'}, {'function.not_source_matches_regex': '(?i)(super\\._update|super\\._mint|super\\._burn|ERC20Upgradeable|_beforeTokenTransfer|assumes caller updates total|_updateSupply\\s*\\()'}, {'function.not_source_matches_regex': '(?is)(_balances|balances|shareOf|sharesOf)\\s*\\[[^\\]]+\\]\\s*-=.*(_balances|balances|shareOf|sharesOf)\\s*\\[[^\\]]+\\]\\s*\\+=|(_balances|balances|shareOf|sharesOf)\\s*\\[[^\\]]+\\]\\s*\\+=.*(_balances|balances|shareOf|sharesOf)\\s*\\[[^\\]]+\\]\\s*-='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — certora-erc20-sum-balances-eq-totalsupply: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
