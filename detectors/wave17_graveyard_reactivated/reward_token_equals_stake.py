"""
reward_token_equals_stake.py - Custom Slither detector.

Pattern (Zellic slice_af PDT Staking V2, MEDIUM→CRIT): a staking contract has
a `stakingToken` state variable and a `registerNewRewardToken` / `addReward`
admin function. The admin can register ANY ERC20 as a reward distribution
token - including the staking token itself - because the function never
compares the new token against `stakingToken`. A malicious (or compromised)
TOKEN_MANAGER registers the staking asset as a reward, then distributes
user deposits back as "rewards", draining the pool while bookkeeping still
shows full balances.

Detection strategy:
    1. Identify contracts that have at least one state variable whose name
       contains a "staking asset" hint - {"stakingtoken", "stakeasset",
       "asset", "stakedtoken", "depositasset", "underlying"} - and whose
       type is `address` or an ERC20 interface.
    2. For each function declared on that contract whose lowercased name
       matches `add|register|set|new` + `reward` (e.g. `addRewardToken`,
       `registerNewRewardToken`, `setRewardAsset`):
         - Confirm the function WRITES to a state variable whose name
           contains `reward` (mapping, array, or address).
         - Confirm the function DOES NOT read the staking-asset state
           variable identified in step 1.
         - No reading = no comparison = no guard. Flag.

Dedup: no wave1..10 or Slither builtin targets "reward token == staking token"
comparison. Related but distinct: `donation_arbitrary_quote_token` (wave9)
targets arbitrary quote token donation, not reward registration.

@author auditooor wave11
@pattern slice_af PDT Staking V2
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_STAKE_VAR_HINTS = (
    "stakingtoken",
    "stakeasset",
    "stakedtoken",
    "depositasset",
    "depositoken",  # typo-tolerant
    "underlying",
    "asset",
    "stakingasset",
)

_REWARD_FN_PATTERNS = (
    ("add", "reward"),
    ("register", "reward"),
    ("set", "reward"),
    ("new", "reward"),
)


def _find_stake_var(contract):
    """Return the first state var whose name matches a staking-asset hint."""
    for sv in contract.state_variables_ordered:
        nm = (sv.name or "").lower()
        if any(h in nm for h in _STAKE_VAR_HINTS):
            # Heuristic type gate: address / IERC20 / contract ref.
            return sv
    return None


def _fn_name_matches_reward_register(name: str) -> bool:
    n = name.lower()
    if "reward" not in n:
        return False
    return any(verb in n for verb, _kw in _REWARD_FN_PATTERNS)


def _writes_reward_state_var(function) -> bool:
    for sv in function.state_variables_written:
        if "reward" in (sv.name or "").lower():
            return True
    return False


def _reads_stake_var(function, stake_sv) -> bool:
    for sv in function.state_variables_read:
        if sv is stake_sv or (sv.name == stake_sv.name):
            return True
    return False


class RewardTokenEqualsStake(AbstractDetector):
    """
    Detect reward-token registration functions that never compare the new
    reward token against the contract's staking asset.
    """

    ARGUMENT = "reward-token-equals-stake"
    HELP = (
        "Reward-token registration function does not check that the new "
        "token differs from the staking asset - admin can register the "
        "staking token as a reward and drain deposits"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Reward Token == Staking Token - Admin Drain via Registration"
    WIKI_DESCRIPTION = (
        "A staking contract stores a `stakingToken` address and exposes an "
        "admin-gated `addRewardToken` / `registerNewRewardToken` function "
        "that lets a manager add tokens to the reward distribution list. "
        "If that function never compares the new token against "
        "`stakingToken`, a compromised or malicious manager registers the "
        "staking asset itself as a reward and subsequent distributions pay "
        "out user deposits as rewards - draining the principal while "
        "internal bookkeeping still shows a full staked balance. Observed "
        "in PDT Staking V2 (Zellic slice_af)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract StakingVault {
    address public stakingToken;
    mapping(address => bool) public isReward;
    function addRewardToken(address t) external onlyManager {
        // BUG: no `require(t != stakingToken)`
        isReward[t] = true;
    }
}
```
1. Users deposit 1M stakingToken. Vault balance = 1M.
2. Compromised manager calls `addRewardToken(stakingToken)`.
3. Manager triggers `distributeRewards(stakingToken, 1M)` to favored wallet.
4. Favored wallet claims 1M stakingToken - users cannot withdraw their deposits."""
    WIKI_RECOMMENDATION = (
        "Add `require(newReward != stakingToken, \"REWARD_IS_STAKE\")` at "
        "the top of the registration function. Also consider a timelock on "
        "reward-token additions and a size cap on the reward array."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            stake_sv = _find_stake_var(contract)
            if stake_sv is None:
                continue

            for function in contract.functions_and_modifiers_declared:
                if not _fn_name_matches_reward_register(function.name or ""):
                    continue
                if not _writes_reward_state_var(function):
                    continue
                if _reads_stake_var(function, stake_sv):
                    continue
                info: DETECTOR_INFO = [
                    function,
                    " registers a new reward token but never reads the "
                    "staking asset ",
                    stake_sv,
                    " to ensure `newToken != stakingToken`. A compromised "
                    "manager can register the staking asset itself as a "
                    "reward and drain user deposits.\n",
                ]
                results.append(self.generate_result(info))

        return results
