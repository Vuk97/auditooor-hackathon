"""
rocketpool-lido-beacon-deposit-credentials-frontrun — generated from reference/patterns.dsl/rocketpool-lido-beacon-deposit-credentials-frontrun.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rocketpool-lido-beacon-deposit-credentials-frontrun.yaml
Source: auditooor-R76-immunefi-rocketpool-lido-$200k-combined
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RocketpoolLidoBeaconDepositCredentialsFrontrun(AbstractDetector):
    ARGUMENT = "rocketpool-lido-beacon-deposit-credentials-frontrun"
    HELP = "Pool stakes 32 ETH to the deposit contract without a pre-commit scheme. A malicious node operator front-runs with 1 ETH under their own withdrawal credentials, capturing the pool's subsequent top-up on the beacon chain."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rocketpool-lido-beacon-deposit-credentials-frontrun.yaml"
    WIKI_TITLE = "ETH2 deposit contract allows front-running of pool staking via withdrawal-credential substitution"
    WIKI_DESCRIPTION = "The canonical ETH 2.0 deposit contract processes `deposit(pubkey, withdrawal_credentials, signature)` without checking whether the pubkey was previously registered under DIFFERENT withdrawal credentials. The beacon chain's `process_deposit` only checks `if pubkey not in validator_pubkeys` — first-seen wins. A staking pool that deposits 32 ETH for a node operator's pubkey is front-runnable: the ope"
    WIKI_EXPLOIT_SCENARIO = "A RocketPool minipool operator generated a pubkey, registered with the pool, and waited for the pool's 32-ETH deposit. Immediately before, they privately deposited 1 ETH to the ETH2 contract for the same pubkey with their own withdrawal credentials. The pool's 32 ETH was credited as a top-up; the operator could exit with the full 33 ETH. $200k combined bounty; Lido froze deposits pending redesign."
    WIKI_RECOMMENDATION = "Use a pre-commit/reveal scheme where the pool verifies the operator's intended withdrawal_credentials hash on-chain BEFORE the 32-ETH deposit is released. Alternatively require operators to post a large slashable bond that a griefer cannot recoup cheaply. Long-term: EIP-7002 triggerable withdrawals "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)RocketPool|Lido|BeaconChain|DepositContract|IDepositContract'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)stake|depositValidator|assignValidator|submitNodeDeposit'}, {'function.body_contains_regex': '(?i)DepositContract\\s*\\.\\s*deposit|IDepositContract|0x00000000219ab540356cbb839cbe05303d7705fa'}, {'function.body_not_contains_regex': '(?i)PreDepositSignatureVerification|predeposit_root|commit_reveal|assertFreshPubkey|pubkey_used\\[|knownValidator\\['}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — rocketpool-lido-beacon-deposit-credentials-frontrun: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
