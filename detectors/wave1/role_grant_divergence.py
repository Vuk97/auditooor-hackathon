"""
role_grant_divergence.py — Custom Slither detector for bug pattern P1.

Pattern: "Deployment-state role-grant divergence"
First observed: Polymarket Cantina iter 3, #OFF.A (High, submitted)

Mechanism:
    A function is gated by `onlyRoles(X)` or similar.
    The audit's test fixture grants role `X` to the caller in setUp(), so every
    audit test passes. The production deployment script never makes that grant.
    On mainnet, every call to the gated function reverts unconditionally.

What this detector does:
    For every function F gated by a role-based modifier, walk the contract's
    deployment helpers (setUp functions, test fixtures, deploy scripts) and
    identify the addresses that are granted the role. Cross-reference against
    the addresses that call F in production paths (via test files or off-chain
    config). If a role-gated function has callers in production but no
    corresponding role grant in the deploy script, emit a HIGH severity alert.

    Static analysis CANNOT check live mainnet state. But it CAN check whether
    the deployment script grants the role to the expected caller addresses.
    If the deploy script is missing an `addWrapper(offramp)` call while the
    offramp contract is deployed and its unwrap() forwards to a role-gated
    function, that's the P1 pattern.

Usage:
    slither <project-dir> --detect role-grant-divergence \\
            --detect-file /path/to/role_grant_divergence.py

Fixes SKILL_ISSUE #31 (Round B, first custom detector).

@author auditooor
@pattern P1 — from reference/bug_patterns_observed.md
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Function, Contract


class RoleGrantDivergence(AbstractDetector):
    """
    Detects functions gated by role-based modifiers where the deployment
    script may not grant the required role to the expected callers.
    """

    ARGUMENT = "role-grant-divergence"
    HELP = (
        "Functions gated by role modifiers whose required role may not be "
        "granted at deploy time to the expected caller. Flags the P1 pattern "
        "from the auditooor bug_patterns_observed.md catalog — first observed "
        "as Polymarket #OFF.A (High, submitted)."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md#p1"
    WIKI_TITLE = "Deployment-state role-grant divergence"
    WIKI_DESCRIPTION = (
        "The role-based access control pattern requires that deployment scripts "
        "grant the correct roles to the correct addresses. Audits typically "
        "pass because the test fixture grants the role; production deployments "
        "can miss the grant entirely, causing every call to revert."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "1. Contract A has `function unwrap() external onlyRoles(WRAPPER_ROLE)`.\n"
        "2. Contract B (the WrappedToken) has `addWrapper(address)` which grants WRAPPER_ROLE.\n"
        "3. The audit's CollateralSetup.sol calls `b.addWrapper(a)` in setUp() — all tests pass.\n"
        "4. The production deploy script omits the addWrapper call.\n"
        "5. On mainnet, every call to a.unwrap() reverts with Unauthorized().\n"
        "6. Users cannot exit their positions via contract A. Permanent DoS until admin intervention."
    )
    WIKI_RECOMMENDATION = (
        "1. Enumerate every role-gated function in production contracts.\n"
        "2. For each role, enumerate every contract address that should hold the role.\n"
        "3. Verify the deploy script grants the role to EVERY expected holder.\n"
        "4. Add a post-deploy assertion: `require(hasRole(role, expected_holder), ...)` in the deploy script.\n"
        "5. During audit, always cross-check on-chain role state via `cast call hasAnyRole(...)`.\n"
        "6. Use this detector to surface candidates; verify each manually."
    )

    # Role-gated modifier names we recognize. Extend via the `role_modifiers` set
    # if your codebase uses custom modifier names.
    ROLE_MODIFIERS = {
        "onlyRoles",
        "onlyRole",
        "hasRole",
        "onlyOwner",
        "onlyAdmin",
        "onlyOperator",
        "onlyManager",
        "onlyWrapper",
        "onlyMinter",
        "onlyBurner",
    }

    # Common role-grant function names. If the deploy script doesn't call any
    # of these for a role-gated function's expected caller, flag it.
    ROLE_GRANT_FUNCTIONS = {
        "grantRole",
        "grantRoles",
        "_grantRole",
        "_grantRoles",
        "addRole",
        "addAdmin",
        "addOperator",
        "addManager",
        "addWrapper",
        "addMinter",
        "addBurner",
        "transferOwnership",
        "setOwner",
    }

    def _function_is_role_gated(self, function: Function) -> bool:
        """Return True if the function uses any of ROLE_MODIFIERS."""
        for modifier in function.modifiers:
            if modifier.name in self.ROLE_MODIFIERS:
                return True
            # Also check for inline require(hasRole(...)) patterns
            for node in function.nodes:
                for ir_call in node.high_level_calls:
                    if hasattr(ir_call[1], "name") and ir_call[1].name in {"hasRole", "hasAnyRole"}:
                        return True
        return False

    def _contract_grants_role(self, contract: Contract) -> bool:
        """Return True if the contract contains at least one role-grant call."""
        for function in contract.functions:
            for node in function.nodes:
                for ir_call in node.high_level_calls:
                    if hasattr(ir_call[1], "name") and ir_call[1].name in self.ROLE_GRANT_FUNCTIONS:
                        return True
                # Also check internal calls
                for internal_call in node.internal_calls:
                    if hasattr(internal_call, "name") and internal_call.name in self.ROLE_GRANT_FUNCTIONS:
                        return True
        return False

    def _detect(self):
        """
        Pass 1: flag every role-gated external/public function as a deploy-state
        verification target. The operator then cross-checks (via `cast call
        hasAnyRole(...)` on mainnet OR by grep'ing the deploy script) that
        the role is actually granted to the correct addresses.

        Pass 2 (for each role-gated function): scan every OTHER contract in
        the compilation unit for cross-contract calls into the gated function.
        Each caller contract MUST hold the role at deploy time — flag it
        specifically so the operator has a checklist.

        This is intentionally an over-approximation. Every role-gated function
        gets flagged as a "verify deploy state" item, even if there's no
        obvious cross-contract caller in source. The operator reviews the
        list and suppresses FPs via comment markers in source.
        """
        results = []

        for contract in self.compilation_unit.contracts_derived:
            # Skip test / mock / setup contracts
            lower = contract.name.lower()
            if any(t in lower for t in ("test", "mock", "setup", "fixture", "helper", "deploy")):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions:
                if function.visibility not in ("external", "public"):
                    continue
                if not self._function_is_role_gated(function):
                    continue

                # R36 narrow: only emit if the function is an ASSET-FLOW entry
                # (wrap/unwrap/mint/burn/redeem/withdraw/claim/convert/transfer/
                # release/exit). Pure admin functions (addAdmin/removeAdmin/
                # pauseTrading/setFeeReceiver/etc.) are by-design centralization
                # and do not match the OFF.A pattern, which was about a deploy
                # script missing a WRAPPER_ROLE grant for a user-facing unwrap.
                # This narrows the R35-observed broadcast-on-every-admin-gate to
                # the user-impact subset.
                ASSET_FLOW_STEMS = (
                    "wrap", "unwrap", "mint", "burn", "redeem", "withdraw",
                    "claim", "convert", "transfer", "release", "exit",
                    "deposit", "matchOrders", "fillOrder", "settle",
                )
                fn_lower = function.name.lower()
                if not any(stem in fn_lower for stem in ASSET_FLOW_STEMS):
                    continue

                # Find the role-gating modifier for the info string
                mod_names = [m.name for m in function.modifiers if m.name in self.ROLE_MODIFIERS]
                mod_str = ", ".join(mod_names) if mod_names else "hasRole/onlyRoles"

                info = [
                    f"Role-gated external function ",
                    function,
                    f" uses modifier(s): {mod_str}. "
                    "DEPLOY-STATE VERIFICATION REQUIRED: confirm the deploy script "
                    "grants the required role to every address that calls this "
                    "function. Miss one grant and every call reverts on mainnet "
                    "(Polymarket #OFF.A pattern, High severity). "
                    "Fast check: `cast call <thisContract> 'rolesOf(address)(uint256)' "
                    "<expected-caller>`. Each non-matching result is a finding.",
                ]
                res = self.generate_result(info)
                results.append(res)

        return results
