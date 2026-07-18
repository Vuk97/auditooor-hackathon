"""
vesting_admin_deposit_impersonation.py - Custom Slither detector.

ARG: vesting-admin-deposit-impersonation
SEVERITY: MEDIUM  CONFIDENCE: LOW

Pattern (from slice_ag - Solera VestingDeposit overwrite):

  A `vestingDeposit(address beneficiary, uint256 amount)` function is callable
  by an admin with an onlyOwner/onlyAdmin/onlyRole modifier AND an `address
  beneficiary` parameter. The function writes `vesting[beneficiary] = amount`
  (or similar schedule/allocation mapping) without checking:
    - that the slot was previously empty (vesting[beneficiary] == 0), OR
    - that the new amount is >= the existing amount.

  An admin can therefore overwrite an existing vesting schedule with a lower
  or zero amount, effectively zeroing out a user's vested tokens.

Detection logic:
  1. Find external/public functions with an admin modifier (name contains
     "onlyOwner", "onlyAdmin", "onlyRole", "onlyOperator", "onlyManager",
     "restricted", "requiresAuth", "admin") and an `address beneficiary`
     parameter (name contains "beneficiary", "recipient", "account", "user").
  2. Confirm the function writes to a state variable whose name contains
     "vesting", "schedule", "allocations", "alloc", "grant", or "award".
  3. Check that NO require/assert node in the function reads the vesting
     state variable in a comparison - proxy for `require(vesting[b] == 0)`.
  4. Flag if (1), (2) are true and (3) finds no guard.

IR observations (verified against fixtures):
  Vulnerable: vestingDeposit writes vesting[beneficiary] with NO require
  reading vesting state var first. Confirmed: no node with
  contains_require_or_assert() AND vesting in node.state_variables_read.

  Clean: vestingDeposit has require(vesting[beneficiary] == 0, "already vested").
  The require node reads vesting state var in node.state_variables_read.
  Confirmed: clean fixture → 0 hits.

Gotchas:
  - Modifier names: `function.modifiers` returns Modifier objects; check their
    names. The modifier body check (does it actually enforce admin?) is not done
    here - name-based matching is the heuristic (acceptable for LOW confidence).
  - Admin modifiers with non-standard names (e.g. `onlyDAO`, `onlyGovernance`)
    will be missed. Extend _ADMIN_MODIFIER_HINTS as needed.
  - The `address beneficiary` parameter search uses case-insensitive substring
    matching against parameter names - catches `_beneficiary`, `toBeneficiary`,
    `recipient`, etc.

Dedup: no Slither builtin covers vesting-admin-overwrite.
  `slither --list-detectors | grep -iE "vesting|schedule|alloc"` → nothing.

Source: reference/corpus_mined/slice_ag.md - Solera VestingDeposit overwrite
@author auditooor wave7
@pattern vesting-admin-deposit-impersonation
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

SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

# Modifier name substrings indicating admin/owner-gated access control.
_ADMIN_MODIFIER_HINTS = (
    "onlyowner",
    "onlyadmin",
    "onlyrole",
    "onlyoperator",
    "onlymanager",
    "onlygovernance",
    "restricted",
    "requiresauth",
    "authorized",
    "auth",
    "onlydao",
    "onlyminter",
    "onlytreasury",
)

# Parameter name substrings indicating a beneficiary / recipient address.
_BENEFICIARY_PARAM_HINTS = (
    "beneficiary",
    "recipient",
    "account",
    "user",
    "to",
    "grantee",
    "investor",
    "holder",
    "wallet",
    "receiver",
)

# State variable name substrings indicating a vesting/allocation mapping.
_VESTING_SV_HINTS = (
    "vesting",
    "schedule",
    "allocations",
    "alloc",
    "grant",
    "award",
    "vest",
    "vestingamount",
    "vestingschedule",
)


def _has_admin_modifier(func) -> bool:
    """
    Return True if the function has any modifier whose name (lowercased) contains
    one of the _ADMIN_MODIFIER_HINTS substrings.
    """
    for mod in func.modifiers:
        mod_name = (getattr(mod, "name", "") or "").lower()
        if any(h in mod_name for h in _ADMIN_MODIFIER_HINTS):
            return True
    return False


def _find_beneficiary_param(func):
    """
    Return the first address-type parameter whose name (lowercased) contains a
    beneficiary hint. Returns None if no such parameter exists.
    """
    for param in func.parameters:
        param_name = (param.name or "").lower()
        # Check if it's an address type
        if "address" not in str(param.type).lower():
            continue
        if any(h in param_name for h in _BENEFICIARY_PARAM_HINTS):
            return param
    return None


def _find_vesting_sv_written(func):
    """
    Return the first state variable written by the function whose name contains
    a vesting/allocation hint. Returns None if no such variable is written.
    """
    for sv in func.state_variables_written:
        sv_name = (sv.name or "").lower()
        if any(h in sv_name for h in _VESTING_SV_HINTS):
            return sv
    return None


def _has_empty_slot_guard(func, vesting_sv) -> bool:
    """
    Return True if any require/assert node in the function reads the vesting
    state variable - proxy for `require(vesting[beneficiary] == 0)`.

    IR pattern (confirmed in clean fixture):
      Index REF -> vesting[beneficiary]
      Binary TMP = REF == 0
      SolidityCall require(bool,string)(TMP, ...)
    The require node has contains_require_or_assert() == True AND
    vesting_sv in node.state_variables_read.
    """
    for node in func.nodes:
        if not node.contains_require_or_assert():
            continue
        if vesting_sv in node.state_variables_read:
            return True
    return False


class VestingAdminDepositImpersonation(AbstractDetector):
    """
    Detect admin-gated vestingDeposit functions that write a vesting/allocation
    mapping without checking that the slot is empty first, enabling the admin
    to overwrite or zero-out an existing user's vested schedule.
    """

    ARGUMENT = "vesting-admin-deposit-impersonation"
    HELP = (
        "Admin vestingDeposit(beneficiary, amount) writes vesting mapping without "
        "require(vesting[beneficiary] == 0) - admin can overwrite existing schedule"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Vesting Admin Deposit - Missing Empty-Slot Guard"
    WIKI_DESCRIPTION = (
        "An admin-gated `vestingDeposit(address beneficiary, uint256 amount)` "
        "function writes `vesting[beneficiary] = amount` without first checking "
        "that the slot is empty (`require(vesting[beneficiary] == 0)`). A "
        "malicious or compromised admin can overwrite a user's existing vesting "
        "schedule with a lower or zero amount, effectively slashing their vested "
        "tokens. Even a non-malicious admin can accidentally clobber a live "
        "schedule during a re-deposit operation. Pattern observed in Solera "
        "(slice_ag VestingDeposit overwrite)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => uint256) public vesting;

function vestingDeposit(address beneficiary, uint256 amount)
    external onlyOwner
{
    vesting[beneficiary] = amount; // no require(vesting[beneficiary] == 0)
}
```
1. Protocol calls `vestingDeposit(alice, 10000e18)` - Alice's vesting = 10000.
2. Admin calls `vestingDeposit(alice, 0)` - Alice's vesting silently overwritten to 0.
3. Alice can no longer withdraw her vested tokens (or receives 0 on claim).
4. Admin has effectively drained Alice's vesting allocation with a single admin tx."""
    WIKI_RECOMMENDATION = (
        "Add `require(vesting[beneficiary] == 0, \"already has schedule\")` at "
        "the start of vestingDeposit. If updating an existing schedule is "
        "intentional, provide a separate `updateVestingDeposit` function that "
        "requires explicit admin justification and emits a detailed event, "
        "ensuring the operation is auditable and the user can verify the change."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                # Only public/external non-constructor functions
                if function.is_constructor:
                    continue
                if type(function).__name__ == "Modifier":
                    continue
                if function.visibility not in ("public", "external"):
                    continue

                # Step 1a: function must have an admin modifier
                if not _has_admin_modifier(function):
                    continue

                # Step 1b: function must have an address beneficiary parameter
                beneficiary_param = _find_beneficiary_param(function)
                if beneficiary_param is None:
                    continue

                # Step 2: function must write a vesting/allocation state variable
                vesting_sv = _find_vesting_sv_written(function)
                if vesting_sv is None:
                    continue

                # Step 3: flag if no require reads the vesting state variable
                if not _has_empty_slot_guard(function, vesting_sv):
                    info: DETECTOR_INFO = [
                        function,
                        " in ",
                        contract,
                        " is an admin function that writes vesting state variable ",
                        vesting_sv,
                        " for beneficiary parameter `"
                        + (beneficiary_param.name or "beneficiary")
                        + "` without checking that the slot is empty "
                        "(no require(vesting[beneficiary] == 0) guard). "
                        "Admin can overwrite an existing vesting schedule. "
                        "Add require(vesting[beneficiary] == 0, 'already has schedule').\n",
                    ]
                    results.append(self.generate_result(info))

        return results
