"""
state_carryover_on_transfer_vesting.py - Custom Slither detector.

Pattern (SecondSwap H-02/03, slice_ab): A vesting-ERC20 contract maintains
per-user vesting state (`stepsClaimed[user]`, `releaseRate[user]`,
`lastClaim[user]`, `vestingState[user]`) but its `transfer` / `_update` /
`_transfer` override does NOT carry that state from sender to receiver. After
a share transfer the recipient inherits a fully unclaimed balance, while the
sender's per-token claim history goes stale → double-claim or vesting reset.

Detection strategy:
    1. For each non-vendored contract that LOOKS like an ERC20 (declares
       `balanceOf` and locally overrides `_update`/`_transfer`/`transfer`).
    2. Find a per-user mapping state variable whose name matches a vesting
       keyword (`stepsClaimed`, `releaseRate`, `vesting`, `claimed`,
       `lastClaim`, `unlockSchedule`, …).
    3. Inspect the body of the transfer override - if it does NOT write to
       any vesting mapping, flag it.

@author auditooor wave9
@pattern slice_ab SecondSwap H-02/03
"""

import re
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.solidity_types import MappingType
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_VESTING_RE = re.compile(
    r"stepsclaimed|stepclaimed|releaserate|release_rate|vesting|claimed|"
    r"lastclaim|last_claim|unlockschedule|unlock_schedule",
    re.IGNORECASE,
)

_HOOK_NAMES = frozenset({
    "_update",
    "_transfer",
    "_beforeTokenTransfer",
    "_afterTokenTransfer",
    "transfer",
})


def _looks_like_erc20(contract) -> bool:
    """Heuristic ERC20 detection - function `balanceOf` must exist anywhere
    in the inheritance chain."""
    for f in contract.functions:
        if (f.name or "") == "balanceOf":
            return True
    return False


class StateCarryoverOnTransferVesting(AbstractDetector):
    """Detect vesting-ERC20 transfer hooks that do not migrate per-user
    vesting state from sender to receiver."""

    ARGUMENT = "state-carryover-on-transfer-vesting"
    HELP = (
        "Vesting-ERC20 transfer hook does not carry per-user vesting "
        "state (stepsClaimed/releaseRate/...) from sender to receiver"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Vesting State Not Carried Over On Transfer"
    WIKI_DESCRIPTION = (
        "Vesting tokens that store per-user state such as `stepsClaimed`, "
        "`releaseRate`, or `lastClaim` must move that state proportionally "
        "whenever shares change hands. When the transfer hook only updates "
        "balances and ignores the vesting bookkeeping, the receiver inherits "
        "a fully unclaimed balance even if the sender had partially vested, "
        "while the sender keeps stale per-token claim history. The result is "
        "double-claim or arbitrary vesting reset by transferring through a "
        "secondary address."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => uint256) public stepsClaimed;

function _update(address from, address to, uint256 a) internal override {
    super._update(from, to, a);
    // BUG: stepsClaimed not migrated
}
```
1. Alice has 100 vested tokens with stepsClaimed[alice] = 5 (5/10 cliffs).
2. Alice transfers 100 tokens to Bob. stepsClaimed[bob] is still 0.
3. Bob calls `claim()` and receives the FULL unlock schedule from step 0,
   double-claiming the 5 cliffs Alice already collected."""
    WIKI_RECOMMENDATION = (
        "In the transfer hook, when both `from` and `to` are non-zero, move "
        "a proportional slice of every vesting mapping from sender to "
        "receiver before the balance update. Encapsulate the migration in "
        "an internal `_carryVesting()` helper so future fields can be added "
        "in one place."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            if not _looks_like_erc20(contract):
                continue

            # Vesting mapping state variables (declared anywhere in this
            # contract's inheritance is fine - the override should still
            # touch them).
            vesting_svs = [
                sv for sv in contract.state_variables
                if isinstance(sv.type, MappingType) and _VESTING_RE.search(sv.name or "")
            ]
            if not vesting_svs:
                continue
            vesting_set = set(vesting_svs)

            for function in contract.functions_and_modifiers_declared:
                if function.name not in _HOOK_NAMES:
                    continue
                # Skip the base declaration we authored ourselves: the hook
                # MUST be an override, i.e. there must be a same-name parent.
                if not function.is_shadowed and function.name == "transfer":
                    # `transfer` declared but no parent? still a candidate
                    pass

                writes_vesting = False
                for node in function.nodes:
                    for sv in node.state_variables_written:
                        if sv in vesting_set:
                            writes_vesting = True
                            break
                    if writes_vesting:
                        break

                if writes_vesting:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " on ",
                    contract,
                    " overrides the share transfer hook but never writes to "
                    "vesting mapping ",
                    vesting_svs[0],
                    " - sender's per-user vesting state is not carried to "
                    "the receiver, enabling double-claim after transfer.\n",
                ]
                results.append(self.generate_result(info))

        return results
