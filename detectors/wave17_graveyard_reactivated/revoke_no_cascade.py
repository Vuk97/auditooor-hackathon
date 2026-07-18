"""
revoke_no_cascade.py - Custom Slither detector for auditooor wave5.

Pattern: "Revoke Without Cascade" - P11
First observed: GTE CLOB (Zellic) + Hyperbeat Pay (Zellic)
Source: reference/corpus_mined/slice_ae.md P11

Mechanism:
    Two-tier permission system:
      Tier 1 - global allowlist:   mapping(address => bool) allowedOperators
      Tier 2 - per-user approvals: mapping(address => mapping(address => bool)) operatorApprovals

    A revoke/remove/disallow function clears Tier 1:
        allowedOperators[op] = false

    But it does NOT clear Tier 2.
    Any user who previously called approveOperator(op) retains a live approval.
    If the on-chain check at usage time is `allowedOperators[op] OR operatorApprovals[user][op]`
    (OR-logic) or if a separate code path checks only Tier 2, the revoked
    operator continues to act on behalf of those users.

    Root cause (GTE CLOB report):
        disallowOperator() writes allowedOperators[op]=false
        but onlySenderOrOperator checks operatorApprovals independently.
        The revoke is incomplete - it should cascade to per-user grants or the
        usage modifier should re-gate on the global allowlist.

What this detector does:
    For every function whose name starts with a "revocation" prefix
    (revoke, remove, disallow, deny, forbid, unapprove):

    1. Collect state_variables_written for that function.
    2. Filter to variables whose names contain auth/operator/admin keywords.
    3. Check whether the SAME contract has ANOTHER mapping whose name
       contains approval/grant/approved keywords AND that second mapping
       is NOT written by the revoke function (cascade gap).
    4. Confirm the second mapping IS written by at least one OTHER function
       (proves the parallel approval layer genuinely exists in the contract).
    5. Flag: revoke-name function + writes auth mapping + misses approval mapping.

ARGUMENT = "revoke-no-cascade"
IMPACT   = MEDIUM
CONFIDENCE = MEDIUM

@author auditooor wave5
@pattern P11 - reference/corpus_mined/slice_ae.md
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.variables.state_variable import StateVariable
from slither.core.solidity_types import MappingType
from slither.utils.output import Output


# ---------------------------------------------------------------------------
# Name-matching helpers
# ---------------------------------------------------------------------------

_REVOKE_PREFIXES = (
    "revoke",
    "remove",
    "disallow",
    "deny",
    "forbid",
    "unapprove",
)

_AUTH_KEYWORDS = (
    "allowed",
    "authorized",
    "operator",
    "admin",
)

_APPROVAL_KEYWORDS = (
    "approval",
    "allowance",
    "approved",
    "grant",
)


def _name_contains_any(name: str, keywords: tuple) -> bool:
    lower = name.lower()
    return any(kw in lower for kw in keywords)


def _is_revoke_function(func_name: str) -> bool:
    lower = func_name.lower()
    return any(lower.startswith(prefix) for prefix in _REVOKE_PREFIXES)


def _is_mapping(sv: StateVariable) -> bool:
    return isinstance(sv.type, MappingType)


class RevokeNoCascade(AbstractDetector):
    """
    Detects revoke/remove/disallow functions that clear a global auth mapping
    but fail to cascade the revocation to a parallel per-user approval mapping.
    """

    ARGUMENT = "revoke-no-cascade"
    HELP = (
        "Revoke/remove/disallow function clears global auth mapping but not the "
        "parallel per-user approval mapping - revoked operator retains live approvals."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/corpus_mined/slice_ae.md#p11"
    WIKI_TITLE = "Revoke Without Cascade - Two-Tier Permission Gap"
    WIKI_DESCRIPTION = (
        "Two-tier operator permission systems often maintain a global allowlist "
        "(e.g. `allowedOperators[op]`) alongside per-user approval mappings "
        "(e.g. `operatorApprovals[user][op]`). When the revocation function "
        "clears only the global tier without invalidating existing per-user "
        "approvals, revoked operators retain the ability to act on behalf of "
        "any user who previously granted them approval. First observed in the "
        "GTE CLOB and Hyperbeat Pay Zellic audits (corpus P11)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => bool) public allowedOperators;
mapping(address => mapping(address => bool)) public operatorApprovals;

function approveOperator(address op) external {
    require(allowedOperators[op], "not allowed");
    operatorApprovals[msg.sender][op] = true;
}

// BUG: clears global allowlist but operatorApprovals[user][op] remains true
function revokeOperator(address op) external {
    allowedOperators[op] = false;  // cascade gap
}

function onlySenderOrOperator(address user) internal view {
    // checks approval independently - revoked op still passes
    require(msg.sender == user || operatorApprovals[user][msg.sender]);
}
```
After `revokeOperator(op)`, any user who previously called `approveOperator(op)`
still has an active per-user grant. If `onlySenderOrOperator` checks only
`operatorApprovals` without re-gating on `allowedOperators`, the revoked
operator can continue placing orders / executing settlements on behalf of users."""
    WIKI_RECOMMENDATION = (
        "When revoking an operator, cascade the revocation to all tiers: "
        "(a) bump a per-operator generation counter so all existing approvals "
        "become stale atomically (preferred - O(1)); OR "
        "(b) delete `operatorApprovals[caller][op]` in the same transaction; OR "
        "(c) re-check `allowedOperators[op]` inside the `onlySenderOrOperator` "
        "modifier so a globally-revoked operator can never pass regardless of "
        "per-user state."
    )

    def _detect(self) -> list[Output]:
        """
        Algorithm:
          For each contract C:
            1. Collect all state mapping vars whose name contains auth keywords
               → auth_maps
            2. Collect all state mapping vars whose name contains approval keywords
               → approval_maps
            3. If either set is empty, skip (no two-tier structure).
            4. Find which approval_maps have a SETTER elsewhere in the contract
               (proves the parallel approval layer is real, not dead code).
            5. For each function F in C whose name is a revocation prefix:
               a. Check F.state_variables_written intersects auth_maps (F writes auth).
               b. Check F.state_variables_written does NOT intersect approval_maps
                  (F does NOT cascade to approval tier).
               c. Check at least one approval_map has a setter (the parallel
                  approval layer exists and is used).
               d. Flag.
        """
        results: list[Output] = []

        for contract in self.contracts:
            # Skip abstract interfaces and test/mock contracts
            lower_name = contract.name.lower()
            if any(t in lower_name for t in ("test", "mock", "setup", "fixture", "interface", "abstract")):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            # Collect state mapping variables grouped by kind
            auth_maps: list[StateVariable] = []
            approval_maps: list[StateVariable] = []

            for sv in contract.state_variables:
                if not _is_mapping(sv):
                    continue
                if _name_contains_any(sv.name, _AUTH_KEYWORDS):
                    auth_maps.append(sv)
                if _name_contains_any(sv.name, _APPROVAL_KEYWORDS):
                    approval_maps.append(sv)

            # Need both tiers to exist for the pattern to apply
            if not auth_maps or not approval_maps:
                continue

            # Identify approval maps that have at least one setter function
            # (function that writes to the approval map, other than constructor)
            approval_map_set = set(approval_maps)
            auth_map_set = set(auth_maps)

            live_approval_maps: set[StateVariable] = set()
            for f in contract.functions_and_modifiers_declared:
                if f.name in ("constructor", "slitherConstructorConstantVariables",
                              "slitherConstructorVariables"):
                    continue
                written = set(f.state_variables_written)
                live_approval_maps |= (written & approval_map_set)

            # No function ever sets the approval map → no real two-tier structure
            if not live_approval_maps:
                continue

            # Now scan for revocation functions
            for f in contract.functions_and_modifiers_declared:
                if not _is_revoke_function(f.name):
                    continue
                if f.visibility not in ("external", "public"):
                    continue

                written = set(f.state_variables_written)

                # Must write at least one auth mapping
                written_auth = written & auth_map_set
                if not written_auth:
                    continue

                # Must NOT write any of the live approval mappings (cascade gap)
                written_approval = written & live_approval_maps
                if written_approval:
                    # Function cascades → not vulnerable
                    continue

                # Build a descriptive info list (source-mapped objects only)
                missing_approval_names = ", ".join(
                    sv.name for sv in sorted(live_approval_maps, key=lambda x: x.name)
                )
                written_auth_names = ", ".join(
                    sv.name for sv in sorted(written_auth, key=lambda x: x.name)
                )

                info: DETECTOR_INFO = [
                    f,
                    " clears auth mapping(s) [",
                    written_auth_names,
                    "] but does NOT cascade to approval mapping(s) [",
                    missing_approval_names,
                    "] - revoked address retains existing per-user approvals "
                    "(P11: revoke-no-cascade). "
                    "Fix: bump a generation counter on revocation or re-gate "
                    "the modifier on the global allowlist.\n",
                ]
                results.append(self.generate_result(info))

        return results
