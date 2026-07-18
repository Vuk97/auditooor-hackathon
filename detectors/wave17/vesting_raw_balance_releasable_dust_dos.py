"""
vesting-raw-balance-releasable-dust-dos - generated from reference/patterns.dsl/vesting-raw-balance-releasable-dust-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vesting-raw-balance-releasable-dust-dos.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VestingRawBalanceReleasableDustDos(AbstractDetector):
    ARGUMENT = "vesting-raw-balance-releasable-dust-dos"
    HELP = "Vesting releasable math uses the vesting contract's raw custody balance. Third-party dust can perturb or brick another user's vesting release calculation."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vesting-raw-balance-releasable-dust-dos.yaml"
    WIKI_TITLE = "Vesting releasable amount derived from raw contract balance"
    WIKI_DESCRIPTION = "A vesting or escrow contract should compute a beneficiary's vested and releasable amount from scheduled accounting, not from the current token/native balance held by the contract or a raw escrow-balance mirror. If `releasable()` uses `token.balanceOf(address(this))`, `address(this).balance`, or `balanceOfEscrow`, any holder can send dust to the contract and change the schedule math for an unrelated beneficiary."
    WIKI_EXPLOIT_SCENARIO = "The vesting contract calculates `vested = token.balanceOf(address(this)) * elapsed / duration` or copies `balanceOfEscrow` into the release path. An attacker transfers 1 wei of the vesting token directly to the contract. The raw balance is now larger than the scheduled allocation, so the next beneficiary release computes against attacker-controlled dust and can revert or mis-account."
    WIKI_RECOMMENDATION = "Store each vesting schedule's total allocation at creation time and compute releasable value from that accounted amount. Keep unsolicited token/native balances in a separate rescue path and never let raw contract balance drive vesting math."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Vesting|Vestable|Escrow|Schedule|Grant|Beneficiary|releasable|claimable)'}, {'contract.has_function_body_matching': '(?i)(balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|address\\s*\\(\\s*this\\s*\\)\\s*\\.balance|balanceOfEscrow|escrowBalance|vestingEscrowBalance)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(releasable|release|claimable|vested|computeVesting|available|withdrawable)'}, {'function.source_matches_regex': '(?i)(balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|address\\s*\\(\\s*this\\s*\\)\\s*\\.balance|balanceOfEscrow|escrowBalance|vestingEscrowBalance)'}, {'function.source_matches_regex': '(?i)(vest|schedule|claim|release|beneficiary|grant)'}, {'function.not_source_matches_regex': '(?i)(totalScheduled|scheduledTotal|totalAllocated|allocatedTotal|trackedBalance|accountedBalance|escrowedPrincipal|principalOwed|syncVesting|checkpointVested|accrue|_accrue|refreshEscrow)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}, {'function.not_in_skip_list': True}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" - vesting-raw-balance-releasable-dust-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
