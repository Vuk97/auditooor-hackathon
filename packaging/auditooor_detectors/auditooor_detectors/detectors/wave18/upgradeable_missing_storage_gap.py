"""
upgradeable_missing_storage_gap.py — Custom Slither detector (wave18 promotion).

Pattern (Zellic slice_ab ANQ Upgradeable-Missing-Storage-Gap, MEDIUM):
An upgradeable contract (inheriting from OpenZeppelin's Initializable /
*Upgradeable base) declares its own state variables but has NO
`uint256[N] private __gap` reserved at the end. A future upgrade that
inserts a new state variable in this base will shift every child-contract
storage slot, silently corrupting user balances and role assignments.

Detection strategy:
    1. A contract is considered "upgradeable" if it (transitively) inherits
       from any contract whose name matches `Initializable`, `*Upgradeable`,
       `UUPSUpgradeable`, `TransparentUpgradeableProxy`, etc.
    2. The contract must declare at least one of its own non-constant,
       non-immutable state variables (otherwise there's nothing to protect).
    3. The contract must NOT declare a state variable named `__gap` (or
       `_gap`, `__storageGap`) of array type.
    4. Skip contracts that are themselves abstract OZ base classes whose
       name matches `*Upgradeable`/`Initializable` — the rule applies to
       the concrete user contracts.

Scope (PR #121 A4): single-version missing-gap detection only. Detecting a
"shrunk gap across versions" failure mode requires diff-aware tooling that
reads two versions of the same file; deferred per Codex backfill plan.

@author auditooor wave10 (graveyard) → wave18 promotion (PR #121 A4)
@pattern slice_ab anq-stablecoin Upgradeable-Missing-Storage-Gap
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
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_UPGRADEABLE_BASE_RE = re.compile(
    r"(Initializable|Upgradeable|UUPSUpgradeable|TransparentUpgradeableProxy|"
    r"ERC1967Upgrade|BeaconProxy)$",
    re.IGNORECASE,
)
_GAP_NAME_RE = re.compile(r"^(__gap|_gap|__storageGap|__storage_gap)$")


def _is_upgradeable(contract) -> bool:
    for base in contract.inheritance:
        if _UPGRADEABLE_BASE_RE.search(base.name):
            return True
    return False


def _is_oz_base(contract) -> bool:
    # Skip the OZ base contracts themselves — we want to flag concrete
    # user contracts that *use* them.
    return bool(_UPGRADEABLE_BASE_RE.search(contract.name))


def _has_gap(contract) -> bool:
    for sv in contract.state_variables_declared:
        if _GAP_NAME_RE.match(sv.name or ""):
            t = str(sv.type or "")
            if "[" in t and "]" in t:
                return True
    return False


def _has_own_storage(contract) -> bool:
    for sv in contract.state_variables_declared:
        # Skip constants and immutables — they don't take storage slots.
        if getattr(sv, "is_constant", False):
            continue
        if getattr(sv, "is_immutable", False):
            continue
        # Skip any reserved gap slots.
        if _GAP_NAME_RE.match(sv.name or ""):
            continue
        return True
    return False


class UpgradeableMissingStorageGap(AbstractDetector):
    """Detect upgradeable contracts that declare state but omit a storage gap."""

    ARGUMENT = "upgradeable-missing-storage-gap"
    HELP = (
        "Upgradeable contract declares state variables but has no "
        "uint256[N] private __gap reserved at the end"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/upgradeable-storage-gap-missing.yaml"
    WIKI_TITLE = "Upgradeable Contract Missing Storage Gap"
    WIKI_DESCRIPTION = (
        "OpenZeppelin's upgradeable base contracts reserve a `uint256[50] __gap` "
        "at the tail of each inheritable contract so future versions can add "
        "state variables without shifting the storage slots of child contracts. "
        "A concrete contract that inherits from an *Upgradeable base and adds "
        "its own state but omits the gap breaks this invariant — any future "
        "upgrade that introduces a new state variable in the parent will "
        "overwrite the child's storage, corrupting balances, roles, and "
        "configuration. ANQ's BaseBridge (Zellic Jan 2026) shipped this bug."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract BaseBridge is OwnableUpgradeable {
    uint256 public totalLocked;
    mapping(address => uint256) public balances;
    // BUG: no __gap
}
contract ChildBridge is BaseBridge {
    uint256 public extraFeature;   // shares slot with next BaseBridge var
}
```
In v2 of BaseBridge the team adds `address public paymaster;`. Every
deployed ChildBridge instance now sees `extraFeature` collide with
`paymaster` — configuration corrupts user balances."""
    WIKI_RECOMMENDATION = (
        "Reserve a gap at the end of every upgradeable base contract: "
        "`uint256[50] private __gap;`. Shrink the array by the number of "
        "newly-added storage slots on each upgrade."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue
            if _is_oz_base(contract):
                continue
            if not _is_upgradeable(contract):
                continue
            if not _has_own_storage(contract):
                continue
            if _has_gap(contract):
                continue

            info: DETECTOR_INFO = [
                contract,
                " is upgradeable (inherits an *Upgradeable base) and declares "
                "its own state variables but reserves no __gap. A future upgrade "
                "that adds a state variable will corrupt child-contract storage.\n",
            ]
            results.append(self.generate_result(info))

        return results
