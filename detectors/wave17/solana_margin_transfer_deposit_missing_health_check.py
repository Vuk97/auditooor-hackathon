"""
solana-margin-transfer-deposit-missing-health-check — generated from reference/patterns.dsl/solana-margin-transfer-deposit-missing-health-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py solana-margin-transfer-deposit-missing-health-check.yaml
Source: auditooor-R76-c4-glow-finance-bug-bounty-28-38-37-36-34-33-29-25-23
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SolanaMarginTransferDepositMissingHealthCheck(AbstractDetector):
    ARGUMENT = "solana-margin-transfer-deposit-missing-health-check"
    HELP = "Margin-owned collateral transfer path mutates position balance but never calls verify_healthy() / assert_healthy() after, enabling immediate under-collateralization and bad-debt creation."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/solana-margin-transfer-deposit-missing-health-check.yaml"
    WIKI_TITLE = "`transfer_deposit` / collateral-move handler skips post-mutation health check → instant bad debt"
    WIKI_DESCRIPTION = "A collateral-move instruction that reduces the amount backing an open position must recompute account valuation and assert health after every token movement. If the handler only checks ownership / authority / token-program constraints but omits `margin_account.valuation(now)?.verify_healthy()?` (or the equivalent `assertSolvent`, `_requireNotLiquidatable`), a borrower with outstanding Claim positi"
    WIKI_EXPLOIT_SCENARIO = "Borrower has 100 USDC collateral backing 50 USDC of outstanding debt. Calls `transfer_deposit(60)` to transfer 60 USDC to a wallet account. Handler succeeds. Post-state: 40 collateral / 50 debt → underwater but no revert. Borrower abandons the account; liquidators cannot recover the full debt."
    WIKI_RECOMMENDATION = "After every balance mutation, invoke the account's health-verification routine unconditionally on the margin-owned withdrawal path (only skip it when the transfer is strictly a DEPOSIT). Add a Hyperthink / invariant fuzz test: for every handler that mutates position balances, `valuation(post).verify"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(margin|lending|perp|vault|borrow).+\\.rs$|_margin_|MarginAccount'}, {'contract.has_state_var_matching': '(?i)Claim|Debt|Borrow|OutstandingDebt'}]
    _MATCH = [{'function.kind': 'handler'}, {'function.name_matches': '(?i)transfer_deposit|withdraw_collateral|move_collateral|reduce_collateral|transfer_position|unwrap_deposit'}, {'function.body_contains_regex': '(?i)set_position_balance|record_transferred_out|token::transfer|transfer_checked|CpiContext::new'}, {'function.body_not_contains_regex': '(?i)verify_healthy|validate_account_health|assert_healthy|require_healthy|check_liquidation|enforce_solvency|require_solvent'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — solana-margin-transfer-deposit-missing-health-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
