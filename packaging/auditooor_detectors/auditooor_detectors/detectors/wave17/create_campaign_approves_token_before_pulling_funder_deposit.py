"""
create-campaign-approves-token-before-pulling-funder-deposit — generated from reference/patterns.dsl/create-campaign-approves-token-before-pulling-funder-deposit.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py create-campaign-approves-token-before-pulling-funder-deposit.yaml
Source: auditooor-R76-rekt-hedgey-finance-2024
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CreateCampaignApprovesTokenBeforePullingFunderDeposit(AbstractDetector):
    ARGUMENT = "create-campaign-approves-token-before-pulling-funder-deposit"
    HELP = "Campaign-creation function grants a token approval to the claim contract BEFORE pulling the funder's deposit via safeTransferFrom. If the pull fails silently (fee-on-transfer, zero amount, attacker-controlled source) the approval persists and tokens already sitting in the contract can be drained."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/create-campaign-approves-token-before-pulling-funder-deposit.yaml"
    WIKI_TITLE = "createCampaign approves downstream claimer before pulling funder deposit, enabling drain via silent-fail transferFrom"
    WIKI_DESCRIPTION = "Vesting / airdrop / lockup protocols commonly let a funder call `createCampaign(token, totalAmount, claimParams)`. Safe implementations pull `totalAmount` via safeTransferFrom FIRST, then approve the downstream claim contract. Buggy implementations do the opposite — or approve unconditionally — so that if the transferFrom fails silently (fee-on-transfer tokens returning less than amount, zero amou"
    WIKI_EXPLOIT_SCENARIO = "Attacker flash-loans 1.3M USDC. Calls `createLockedCampaign(USDC, 1.3M, attackerClaimContract)`. Contract approves `attackerClaimContract` for 1.3M USDC on the global campaign-holder contract. Contract then calls `USDC.transferFrom(attacker, this, 1.3M)` which succeeds. Attacker calls `attackerClaimContract.claim()` which pulls 1.3M + any pre-existing USDC parked on the campaign-holder. Attacker r"
    WIKI_RECOMMENDATION = "Pull funds FIRST, verify receipt with a balance delta check, then approve. Pattern: `uint256 pre = token.balanceOf(this); token.safeTransferFrom(funder, this, amount); require(token.balanceOf(this) - pre == amount, 'bad deposit'); token.safeApprove(claimer, amount);`. Never grant unbounded or pre-de"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'Function takes a deposit from a funder via transferFrom AND approves / allowance-grants a downstream claim contract, with the approval granted before the transfer completes.']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)createLockedCampaign|createAirdrop|createCampaign|createVesting|createLockup|createClaim'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.body_contains_regex': '(?i)safeApprove|approve\\s*\\(\\s*\\w+claim|approve\\s*\\(\\s*address\\(this\\)|allowance\\s*\\[.*\\]\\s*='}, {'function.body_not_contains_regex': '(?i)safeTransferFrom\\s*\\([^;]*\\)\\s*;\\s*(IERC20|_token|token)\\.(safeApprove|approve)|balanceOf\\(address\\(this\\)\\)\\s*-\\s*preBal|_receivedAmount|actualDeposited'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — create-campaign-approves-token-before-pulling-funder-deposit: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
