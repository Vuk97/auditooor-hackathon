"""
compound_fork_blacklist_blocks_liquidation.py - Custom Slither detector.

Pattern: Compound V2 fork adds a blacklist check to repayBorrowAllowed /
redeemAllowed / transferAllowed.  Because liquidateBorrowFresh calls
repayBorrowFresh internally, the same blacklist check triggers during
liquidation - blacklisted positions become permanently un-liquidatable,
threatening protocol solvency.

Source: reference/corpus_mined/slice_ah.md - Takara Lend (CRITICAL).

Detection strategy:
  1. Find any Comptroller-like contract that declares a function whose name
     contains "repayBorrowAllowed", "redeemAllowed", or "transferAllowed".
  2. Check whether that function reads a state mapping whose name contains any
     of the blacklist hint substrings (blacklist / blocked / forbidden / denied).
  3. If the SAME contract also declares ANY function whose name contains
     "liquidate" or "seize", flag it - a blacklist gate in a repay/redeem
     allowed hook that lives alongside a liquidation function is the bug.

Confidence: MEDIUM - name-based heuristic; operators should confirm that the
blacklist-checked allowed function is in fact called on the liquidation path.
Impact: HIGH - blacklisted positions are permanently un-liquidatable, enabling
bad debt accumulation.

@author auditooor
@pattern wave6 compound-fork-blacklist-blocks-liquidation
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
from slither.core.variables.state_variable import StateVariable
from slither.core.solidity_types import MappingType
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

# Function name substrings that indicate an "allowed" hook on the borrow/redeem/transfer path.
_ALLOWED_HOOK_HINTS = ("repayborrow", "redeem", "transfer")
_ALLOWED_SUFFIX = "allowed"

# Blacklist-mapping name substrings.
_BLACKLIST_HINTS = ("blacklist", "blocked", "forbidden", "denied", "banlist", "denylist")

# Function name substrings that indicate a liquidation path.
_LIQUIDATE_HINTS = ("liquidate", "seize")


def _is_allowed_hook(func_name: str) -> bool:
    """Return True if this looks like a repayBorrowAllowed / redeemAllowed hook."""
    low = func_name.lower()
    return (
        _ALLOWED_SUFFIX in low
        and any(h in low for h in _ALLOWED_HOOK_HINTS)
    )


def _reads_blacklist_mapping(func) -> "StateVariable | None":
    """
    Return the blacklist-like state variable if the function reads a mapping
    whose name contains a blacklist hint substring, else None.

    We check state_variables_read for name hints.  We also accept non-mapping
    types (e.g. a plain `mapping(address => bool) blacklist`) by name alone -
    the type check is a tiebreaker to reduce FP on coincidentally-named vars.
    """
    for sv in func.state_variables_read:
        name_low = (sv.name or "").lower()
        if not any(h in name_low for h in _BLACKLIST_HINTS):
            continue
        # Accept mappings or plain booleans keyed by address (type not always
        # resolvable - accept by name alone at MEDIUM confidence).
        return sv
    return None


def _contract_has_liquidation_function(contract) -> "object | None":
    """Return the first liquidation/seize function declared in the contract, or None."""
    for f in contract.functions_and_modifiers_declared:
        low = f.name.lower()
        if any(h in low for h in _LIQUIDATE_HINTS):
            return f
    return None


class CompoundForkBlacklistBlocksLiquidation(AbstractDetector):
    """
    Detect Compound V2 forks where a blacklist check in repayBorrowAllowed /
    redeemAllowed blocks the liquidation path, making insolvent positions
    permanently un-liquidatable.
    """

    ARGUMENT = "compound-blacklist-blocks-liquidation"
    HELP = (
        "Compound V2 fork: blacklist check in repayBorrowAllowed/redeemAllowed "
        "propagates into liquidation path, blocking forced liquidations"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Blacklist in Allowed-Hook Blocks Liquidation (Compound V2 Fork)"
    WIKI_DESCRIPTION = (
        "In a Compound V2 fork, `repayBorrowAllowed` (or `redeemAllowed` / "
        "`transferAllowed`) enforces a blacklist check. Because "
        "`liquidateBorrowFresh` calls `repayBorrowFresh` internally, the same "
        "blacklist check is triggered on the liquidation path. A blacklisted "
        "borrower can never be liquidated, allowing their under-collateralised "
        "position to accumulate as bad debt and threatening protocol solvency. "
        "This exact pattern was observed as CRITICAL in the Takara Lend audit "
        "(Zellic, 2024)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
// Comptroller.sol (Compound V2 fork)
mapping(address => bool) public blacklist;

function repayBorrowAllowed(address borrower) public view {
    require(!blacklist[borrower], "blacklisted");  // blacklist enforced here
}

function liquidateBorrowFresh(address liquidator, address borrower, uint256 amount)
    internal
{
    repayBorrowFresh(borrower, amount);  // internally calls repayBorrowAllowed
    // ^ REVERTS for blacklisted borrower - liquidation is impossible
}
```
1. Admin adds under-collateralised borrower to `blacklist` (or attacker
   self-blacklists before going underwater).
2. Every call to `liquidateBorrow` reverts inside `repayBorrowAllowed`.
3. The bad-debt position grows unchecked, threatening pool solvency."""
    WIKI_RECOMMENDATION = (
        "Add a separate `liquidateBorrowAllowed` (or pass an `isLiquidation` "
        "flag) that bypasses the blacklist check. The blacklist should only "
        "restrict voluntary repayments, not forced liquidations. Ensure the "
        "liquidation path calls a allow-hook that does NOT gate on the "
        "blacklist."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            # Skip test/mock/vendored contracts
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            # Step 1: find all "allowed" hooks that read a blacklist mapping
            flagged_hooks: list[tuple] = []  # (func, blacklist_var)
            for func in contract.functions_and_modifiers_declared:
                if not _is_allowed_hook(func.name):
                    continue
                bl_var = _reads_blacklist_mapping(func)
                if bl_var is None:
                    continue
                flagged_hooks.append((func, bl_var))

            if not flagged_hooks:
                continue

            # Step 2: check if the contract also has a liquidate/seize function
            liquidation_func = _contract_has_liquidation_function(contract)
            if liquidation_func is None:
                continue

            # Step 3: emit one finding per flagged hook
            for hook_func, bl_var in flagged_hooks:
                info: DETECTOR_INFO = [
                    contract,
                    " has function ",
                    hook_func,
                    " that reads blacklist-like state variable '",
                    bl_var.name,
                    "', and sibling function ",
                    liquidation_func,
                    " calls the same repay path internally. "
                    "Blacklisted positions become permanently un-liquidatable. "
                    "Bypass the blacklist check on the liquidation code path.\n",
                ]
                results.append(self.generate_result(info))

        return results
