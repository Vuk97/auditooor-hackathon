"""
bonding_shares_unstake_on_transfer.py - Custom Slither detector.

Pattern (GTE Launchpad slice_ac MED - Bonding-Shares-Reduced-On-Transfer):
An ERC-20 LaunchToken overrides `_update` / `_transfer` / `_beforeTokenTransfer`
and, inside the override, calls an `_unstake` / `_unbond` / `_decreaseStake`
helper against the `from` address. Transferring tokens therefore reduces
the sender's bonding shares - completely unrelated to any user action - and
rewards accrued to those shares leak to the protocol, not the user.

Detection strategy:
    1. Find ERC-20-like contracts (have a function named `transfer` or
       `_transfer`).
    2. Find a locally-declared transfer hook
       (`_update`/`_transfer`/`_beforeTokenTransfer`/`_afterTokenTransfer`).
    3. Inside the hook, look for an internal call whose callee name matches
       `_?(unstake|unbond|decreasestake|unlock|withdrawstake|reducestake)`.
    4. If found → flag the hook.

This is distinct from existing detectors:
    - `checkpoint_cleared_on_transfer_erc721` (zeros a checkpoint array)
    - `erc4626_principal_not_updated_on_transfer` (fails to MOVE principal)
    - `dirty_flag_not_updated_on_transfer` (fails to update a flag)
This detector fires on the opposite failure: the hook ACTIVELY unwinds the
sender's stake on every transfer.

@author auditooor wave11
@pattern slice_ac GTE Launchpad - Bonding-Shares-Reduced-On-Transfer
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
from slither.slithir.operations import InternalCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_HOOK_NAMES = frozenset({
    "_update",
    "_transfer",
    "_beforetokentransfer",
    "_aftertokentransfer",
})

_UNSTAKE_RE = re.compile(
    r"^_?(unstake|unbond|decrease_?stake|unlock|withdraw_?stake|reduce_?stake|exit_?stake)$",
    re.IGNORECASE,
)


def _is_erc20_like(contract) -> bool:
    names = {(f.name or "").lower() for f in contract.functions_and_modifiers_declared}
    names |= {(f.name or "").lower() for f in contract.functions}
    return "transfer" in names or "_transfer" in names or "balanceof" in names


class BondingSharesUnstakeOnTransfer(AbstractDetector):
    """Flag token transfer hook that actively unstakes the sender."""

    ARGUMENT = "bonding-shares-unstake-on-transfer"
    HELP = (
        "ERC-20 transfer hook calls _unstake/_unbond against the sender - "
        "plain transfers silently unwind bonding stake"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Bonding Shares Unstaked On Transfer"
    WIKI_DESCRIPTION = (
        "An ERC-20 LaunchToken's `_update` hook calls an `_unstake` helper "
        "against the `from` address on every transfer. Any transfer "
        "inadvertently unwinds the sender's bonding position and the rewards "
        "accrued to those shares are re-distributed away from the user. "
        "Reported in GTE Launchpad."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function _update(address from, address to, uint256 a) internal override {
    if (from != address(0)) _unstake(from, a); // BUG
    super._update(from, to, a);
}
```
Alice transfers 1 token to Bob. Alice's bonding shares are silently reduced
and her accrued rewards are lost. Bob receives the token but no stake."""
    WIKI_RECOMMENDATION = (
        "Do not mutate staking/bonding state from transfer hooks. Unstake "
        "should happen only when the user calls an explicit unstake function."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue
            if not _is_erc20_like(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if (function.name or "").lower() not in _HOOK_NAMES:
                    continue
                bad_call_node = None
                bad_name = None
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, InternalCall):
                            continue
                        callee = ir.function
                        if callee is None:
                            continue
                        cname = getattr(callee, "name", "") or ""
                        if _UNSTAKE_RE.match(cname):
                            bad_call_node = node
                            bad_name = cname
                            break
                    if bad_call_node is not None:
                        break
                if bad_call_node is None:
                    continue
                info: DETECTOR_INFO = [
                    function,
                    " calls ",
                    bad_call_node,
                    f" ({bad_name}) on every transfer - plain transfers unwind bonding stake.\n",
                ]
                results.append(self.generate_result(info))

        return results
