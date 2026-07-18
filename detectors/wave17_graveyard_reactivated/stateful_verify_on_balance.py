"""
stateful_verify_on_balance.py - Custom Slither detector.

Pattern: permissionless external/public function whose name matches the
verify*/processOracle*/proveWithdraw*/verifyAndProcess*/processProof* family
AND writes to a balance-like state variable (shares, balances, deposits,
collateral, stake) WITHOUT either:
  (a) an onlyOwner/onlyAdmin ACL modifier, OR
  (b) a require/assert node that reads msg.sender.

Source: reference/corpus_mined/slice_aa.md P10 - EigenLayer EIG-19
  (`verifyBalanceUpdate()` permissionless, anyone with a valid proof can
  decrease pod owner's shares before the owner processes withdrawal), Mantle
  (`processNextOracleRecords` callable by anyone, enabling first-deposit
  inflation), StakeWise (oracle/proof entry-points without caller gates).

Detection strategy:
  1. Walk c.functions_and_modifiers_declared; filter external/public only.
  2. Match function name (lowercase) against VERIFY_PATTERN (compiled regex).
  3. Check f.state_variables_written for any variable whose name contains a
     BALANCE_HINTS token - if none, skip (function is safe or irrelevant).
  4. Check f.modifiers: if any modifier name (lowercase) is in ACL_MODIFIERS,
     skip (admin-gated).
  5. Walk function nodes: if any node has contains_require_or_assert() AND
     node.solidity_variables_read contains msg.sender → skip (user-gate present).
  6. If all three checks pass (pattern match + balance write + no gate) → flag.

API notes confirmed by IR probe:
  - f.state_variables_written lists StateVariable objects across all IR.
    Name access: sv.name - reliable.
  - node.solidity_variables_read returns SolidityVariable /
    SolidityVariableComposed objects. msg.sender has .name == "msg.sender".
  - node.contains_require_or_assert() is the canonical pre-built helper
    (from tx_origin.py canonical pattern).
  - f.modifiers returns Modifier objects; access names via .name.
  - No Assignment import needed - we read f.state_variables_written directly,
    which Slither pre-computes by walking all IR lvalue assignments.

Confidence: MEDIUM - a function named verifyX that writes shares without a
caller check is a strong signal. FP risk: functions that do msg.sender checks
inside an internal helper called from the verify* function (callee not
inspected - acceptable approximation for triage). Use HIGH impact because
arbitrary reduction of user balances/shares directly enables fund extraction.

Dedup check (run before writing):
  slither --list-detectors | grep -i 'verify\\|proof\\|balance'
  → Only hit: `reentrancy-balance` (#24) - detects outdated balance AFTER
    reentrancy. Completely orthogonal: that detector checks ordering of
    balance reads relative to external calls; ours checks absence of caller
    authentication on verify* writes. No overlap.

@author auditooor
@pattern wave5 / P10 - EigenLayer/Mantle/StakeWise permissionless verify class
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


# Function names that look like proof/oracle verification entry-points.
# These are the canonical names from EigenLayer, Mantle, StakeWise findings.
# Compiled once at import time for performance across large contract sets.
_VERIFY_PATTERN = re.compile(
    r"(verify|processProof|processOracle|proveWithdraw|verifyAndProcess)",
    re.IGNORECASE,
)

# State variable name substrings that indicate the write is balance-critical.
# Writes to these vars without a caller gate are the actual vulnerability.
_BALANCE_HINTS = (
    "balance",
    "share",
    "deposit",
    "collateral",
    "stake",
)

# Modifier names (lowercased) we accept as "function is sufficiently gated".
# An admin modifier is a complete mitigation - even if any-caller can call
# the function, the modifier blocks non-admins before the balance write.
_ACL_MODIFIERS = frozenset({
    "onlyowner",
    "onlyadmin",
    "onlyoperator",
    "onlyroles",
    "onlyrole",
    "hasrole",
    "hasanyrole",
    "requiresauth",
    "authorized",
    "onlymanager",
    "onlygovernance",
    "onlymultisig",
    "onlymaintainer",
    "onlywrapper",
    "onlyproxy",
    "restricted",
})

# Skip test/mock/fixture files to reduce noise from test contracts.
SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _name_matches_verify_pattern(function_name: str) -> bool:
    """Return True if the function name contains a verify/processOracle/... token."""
    return bool(_VERIFY_PATTERN.search(function_name))


def _writes_balance_state(function) -> "StateVariable | None":
    """
    Return the first balance-like state variable the function writes to,
    or None if no such variable is written.

    Uses f.state_variables_written - Slither's pre-computed list of every
    StateVariable written by any IR node in the function. Name matching is
    case-insensitive substring check.
    """
    for sv in function.state_variables_written:
        name = (sv.name or "").lower()
        if any(hint in name for hint in _BALANCE_HINTS):
            return sv
    return None


def _has_acl_modifier(function) -> bool:
    """
    Return True if the function carries any modifier whose name (lowercased)
    appears in the ACL_MODIFIERS set. Modifier names are read directly from
    function.modifiers - the list returned by Slither for all modifier
    applications on the function declaration.
    """
    for m in function.modifiers:
        if (m.name or "").lower() in _ACL_MODIFIERS:
            return True
    return False


def _has_msgsender_require(function) -> bool:
    """
    Return True if any node in the function body satisfies BOTH:
      - node.contains_require_or_assert()  (a guard node)
      - 'msg.sender' appears in node.solidity_variables_read

    This detects the pattern `require(msg.sender == user, ...)` which is the
    minimal correct mitigation for self-modification.

    API note: node.solidity_variables_read returns SolidityVariableComposed
    objects; msg.sender has .name == "msg.sender" (canonical Slither spelling).
    The check does NOT fire on `token.transfer(msg.sender, ...)` because that
    node does not contain a require/assert (canonical pattern from _skip_log.md
    gotcha #19 - distinguishing guard vs transfer usage of msg.sender).
    """
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        for sv in node.solidity_variables_read:
            if sv.name == "msg.sender":
                return True
    return False


class StatefulVerifyOnBalance(AbstractDetector):
    """
    Detect permissionless verify*/processOracle*/proveWithdraw* functions
    that write to balance/share/deposit state without a caller guard.
    """

    ARGUMENT = "stateful-verify-on-balance"
    HELP = (
        "Permissionless verify*/processOracle* function writes to balance/share "
        "state without msg.sender == user check or admin modifier"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Permissionless Verify Function Modifies User Balance"
    WIKI_DESCRIPTION = (
        "External/public functions whose names contain 'verify', 'processProof', "
        "'processOracle', 'proveWithdraw', or 'verifyAndProcess' accept external "
        "proof/oracle data and write to balance-like state variables (shares, "
        "balances, deposits, collateral, stake). If the function lacks both an "
        "admin modifier AND an explicit msg.sender == affected_user check, any "
        "caller can supply a valid-but-harmful proof to reduce another user's "
        "balance before that user can process their own withdrawal. Confirmed in "
        "EigenLayer (EIG-19: verifyBalanceUpdate), Mantle (processNextOracleRecords "
        "enables inflation attack), and StakeWise (oracle entry-points without gates)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => uint256) public shares;

function verifyWithdrawalProof(address user, bytes calldata proof) external {
    require(_verify(proof), "bad proof");
    shares[user] -= 100;  // no msg.sender check, no admin modifier
}
```
1. Victim has `shares[victim] = 1000`.
2. Attacker constructs a valid proof for victim's address.
3. Attacker calls `verifyWithdrawalProof(victim, attacker_proof)` repeatedly.
4. Each call reduces `shares[victim]` without the victim's consent.
5. Victim's withdrawable balance is slashed to zero; victim suffers a direct loss.
In the EigenLayer context (EIG-19) this allowed frontrunning a pod owner's
withdrawal: attacker calls verifyBalanceUpdate to decrease shares before the
owner calls queueWithdrawals, reducing the owner's queued amount."""
    WIKI_RECOMMENDATION = (
        "Add `require(msg.sender == user, \"caller must be affected user\")` inside "
        "the function body, or gate the function with an onlyOwner/onlyAdmin modifier "
        "if proof submission is an admin-only operation. If the function must remain "
        "permissionless (e.g. a relayer pattern), ensure the proof itself cryptographically "
        "binds the caller address so that a proof valid for user X cannot be submitted "
        "by any address other than X."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            # Skip test/fixture/mock contracts by name to reduce noise.
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                # Step 1: only external/public entry-points are exploitable.
                if function.visibility not in ("external", "public"):
                    continue

                # Step 2: constructors and pure/view functions never write state
                # in the vulnerable way - skip them early.
                if function.is_constructor:
                    continue

                # Step 3: name must match the verify/processOracle/... family.
                if not _name_matches_verify_pattern(function.name):
                    continue

                # Step 4: function must write to a balance-like state variable.
                # If it doesn't touch balances/shares/deposits, there's no risk.
                balance_var = _writes_balance_state(function)
                if balance_var is None:
                    continue

                # Step 5: if an ACL modifier is present, the function is gated -
                # only admins can call it, so attacker cannot exploit.
                if _has_acl_modifier(function):
                    continue

                # Step 6: if the function contains require(msg.sender == ...) the
                # developer has added a per-user self-modification guard - safe.
                if _has_msgsender_require(function):
                    continue

                # All checks passed: flag the function.
                info: DETECTOR_INFO = [
                    function,
                    " is a permissionless verify/processOracle/proveWithdraw "
                    "function that writes to balance-like state variable ",
                    balance_var,
                    " without an admin modifier or msg.sender == user guard. "
                    "Any caller can submit a proof on behalf of another user "
                    "and reduce their balance. Add require(msg.sender == user) "
                    "or an onlyOwner/onlyAdmin modifier.\n",
                ]
                results.append(self.generate_result(info))

        return results
