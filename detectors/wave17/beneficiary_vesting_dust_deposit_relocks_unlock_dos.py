"""
beneficiary-vesting-dust-deposit-relocks-unlock-dos — generated from reference/patterns.dsl/beneficiary-vesting-dust-deposit-relocks-unlock-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py beneficiary-vesting-dust-deposit-relocks-unlock-dos.yaml
Source: auditooor-W6-8-worker-bf
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BeneficiaryVestingDustDepositRelocksUnlockDos(AbstractDetector):
    ARGUMENT = "beneficiary-vesting-dust-deposit-relocks-unlock-dos"
    HELP = "An arbitrary-beneficiary vesting deposit path rewrites that beneficiary's unlock/release time on every deposit, but has no meaningful minimum-amount floor or self-only/auth guard. An attacker can spend dust to keep relocking the victim."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/beneficiary-vesting-dust-deposit-relocks-unlock-dos.yaml"
    WIKI_TITLE = "Dust deposit can relock another beneficiary's vesting"
    WIKI_DESCRIPTION = "Some vesting and bond contracts expose a `depositFor(address beneficiary, uint256 amount)` or similar entry point that both transfers assets in and rewrites the beneficiary's vesting metadata (`releaseTime`, `unlockTime`, `vestingEnd`, `bondInfo[beneficiary].vesting`, etc.). If the function accepts arbitrarily small amounts and any caller may target any beneficiary, an attacker only needs a dust d"
    WIKI_EXPLOIT_SCENARIO = "A vesting escrow exposes `depositFor(beneficiary, amount)`. Each call executes `token.safeTransferFrom(msg.sender, address(this), amount); releaseTime[beneficiary] = block.timestamp + vestingTerm;`. The attacker repeatedly calls `depositFor(victim, 1)` once per day. Every call costs only dust but resets the victim's release time to a full new vesting term, so `claim()` never becomes available."
    WIKI_RECOMMENDATION = "Require either a meaningful minimum amount (`require(amount >= MIN_VESTING_DEPOSIT)`) so the grief cost scales with the harm, or restrict the path so only the beneficiary / a trusted role may extend the schedule. If additional deposits are allowed, preserve already-accrued vesting instead of blindly"

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i)(vesting|unlock|releaseTime|cliff|maturity|bondInfo|vestingTerm)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(deposit|depositFor|vest|vestFor|fund|lock|stake|bond)'}, {'function.has_param_of_type': 'address'}, {'function.has_param_name_matching': '(?i)(beneficiary|recipient|user|account|to)'}, {'function.has_param_name_matching': '(?i)(amount|value|qty)'}, {'function.body_contains_regex': '(?i)(transferFrom|safeTransferFrom)'}, {'function.body_contains_regex': '(?i)(releaseTime|unlockTime|unlockAt|vestingEnd|vestingStart|maturity|cliff|bondInfo)\\s*\\['}, {'function.body_contains_regex': '(?i)(releaseTime|unlockTime|unlockAt|vestingEnd|vestingStart|maturity|cliff|vestingTerm)\\s*=|block\\.timestamp\\s*\\+\\s*(vesting|unlock|term|duration)'}, {'function.body_not_contains_regex': '(?i)(MIN_(VEST|DEPOSIT|AMOUNT)|minVest|minDeposit|minAmount|minimum\\s+deposit|amount\\s*>?=\\s*MIN_|msg\\.sender\\s*==\\s*(beneficiary|recipient|user|account|to)|require\\s*\\(\\s*(beneficiary|recipient|user|account|to)\\s*==\\s*msg\\.sender|onlyOwner|onlyRole|_checkRole|hasRole)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — beneficiary-vesting-dust-deposit-relocks-unlock-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
