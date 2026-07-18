"""
pashov-reward-per-token-not-synced-on-deposit

Fixture-smoke/source-shape detector for a StakeDAO-style deposit path that
copies `extraRewardPerToken[token]` into a per-user
`checkpoint.rewardPerTokenPaid[token]` slot before any reward-state refresh for
that deposit. Submission posture: NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_FUNCTION_NAME_RE = re.compile(r"(?i)^(?:_deposit|deposit|stake|depositAssets|depositShares|enter)$")
_CONTRACT_CONTEXT_RE = re.compile(
    r"(?i)\b(?:extraRewardPerToken|rewardPerTokenPaid|RewardVault|StrategyWrapper|rewardTokens)\b"
)
_CHECKPOINT_ASSIGN_RE = re.compile(
    r"(?is)(?:checkpoint\s*\.\s*rewardPerTokenPaid|rewardPerTokenPaid|userRewardPerTokenPaid)"
    r"\s*\[[^\]]+\]\s*=\s*extraRewardPerToken\s*\[[^\]]+\]"
)
_UPDATE_CALL_RE = re.compile(
    r"(?i)\b(?:_updateExtraRewardState|_updateRewards|updateReward|_syncRewards|"
    r"accrueRewards|claimExtraRewards|claimRewards|checkpointRewards)\s*\("
)
_BALANCE_MUTATION_RE = re.compile(
    r"(?is)(?:checkpoint\s*\.\s*balance|_balances|balances|totalSupply|_totalSupply)"
    r"\s*(?:\[[^\]]+\])?\s*\+\="
)
_REWARD_LOOP_RE = re.compile(r"(?is)for\s*\(.*?(?:rewardTokens|extraRewards|rewardT)")


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _first_match_start(pattern: re.Pattern[str], text: str) -> int | None:
    match = pattern.search(text)
    return match.start() if match else None


def _has_unsynced_reward_per_token_snapshot_shape(src: str) -> bool:
    assign_at = _first_match_start(_CHECKPOINT_ASSIGN_RE, src)
    if assign_at is None:
        return False
    if not _REWARD_LOOP_RE.search(src):
        return False
    if not _BALANCE_MUTATION_RE.search(src):
        return False

    update_at = _first_match_start(_UPDATE_CALL_RE, src)
    if update_at is not None and update_at < assign_at:
        return False
    return True


class PashovRewardPerTokenNotSyncedOnDeposit(AbstractDetector):
    ARGUMENT = "pashov-reward-per-token-not-synced-on-deposit"
    HELP = (
        "Deposit path snapshots per-user `rewardPerTokenPaid[token]` from "
        "`extraRewardPerToken[token]` before refreshing extra reward state, "
        "letting pre-existing emissions be redistributed across the new "
        "post-deposit supply."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "pashov-reward-per-token-not-synced-on-deposit.yaml"
    )
    WIKI_TITLE = "Deposit snapshots extra reward checkpoints before reward state refresh"
    WIKI_DESCRIPTION = (
        "A wrapper deposit loop copies `extraRewardPerToken[token]` into the "
        "depositor's checkpoint without first calling the reward-state refresh "
        "helper for that deposit. Any emissions accrued since the last sync "
        "remain priced against the stale global accumulator."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "User A stays deposited while extra rewards accrue off-chain or in a "
        "reward vault. User B deposits immediately before the next reward "
        "refresh. Because B's checkpoint was copied from a stale "
        "`extraRewardPerToken[token]`, the later refresh divides the backlog "
        "across the larger total supply and B captures emissions that belonged "
        "to earlier depositors."
    )
    WIKI_RECOMMENDATION = (
        "Refresh extra reward state before any deposit-time checkpoint write. "
        "Route every supply-mutating entry point through the same reward-sync "
        "helper, then snapshot the user's `rewardPerTokenPaid` values."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_src = _source(contract)
            if not _CONTRACT_CONTEXT_RE.search(contract_src):
                continue

            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if not _FUNCTION_NAME_RE.search(function.name or ""):
                    continue

                function_src = _source(function)
                if not _CONTRACT_CONTEXT_RE.search(function_src):
                    continue
                if not _has_unsynced_reward_per_token_snapshot_shape(function_src):
                    continue

                info = [
                    function,
                    (
                        " — pashov-reward-per-token-not-synced-on-deposit: "
                        "deposit snapshots extra reward checkpoints before any "
                        "reward-state refresh."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
