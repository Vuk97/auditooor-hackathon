// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

// =============================================================================
// auditooor — Fork test template
//
// Use this template when the finding depends on LIVE mainnet state
// (missing role grants, stale config, post-audit regressions, immutables).
//
// The test runs against a public RPC via vm.createSelectFork, so no local
// reproduction of the setup is needed. Replace the marked sections with your
// target's addresses and function signatures.
// =============================================================================

import { Test, Vm } from "@forge-std/src/Test.sol";

// Minimal interfaces — add only what your PoC needs. Avoid pulling full project
// interfaces; they bloat compile time and increase dependency risk.

interface ITarget {
    function vulnerableFunction(address _asset, address _to, uint256 _amount) external;
}

interface IERC20Like {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

/// @title MyFindingPoC
/// @notice Replace with a 2-line description of the finding and its severity.
///         Example: Proves that CollateralOfframp.unwrap() reverts on every
///         call on mainnet because the Offramp lacks WRAPPER_ROLE on the
///         CollateralToken proxy. High severity (permanent DoS).
contract MyFindingPoC is Test {
    // =============== CONFIGURATION ==================================

    // Mainnet addresses — replace with your targets.
    address constant TARGET          = 0x0000000000000000000000000000000000000000;
    address constant SUPPORTING      = 0x0000000000000000000000000000000000000000;
    address constant TEST_TOKEN      = 0x0000000000000000000000000000000000000000;

    // The RPC URL for the target chain. Polygon: https://polygon.drpc.org
    // Ethereum: your preferred mainnet RPC
    string constant RPC = "https://polygon.drpc.org";

    // Test accounts
    address user = address(0xBEEF);

    // Specific error selector you expect the call to revert with.
    // Look up with: cast sig 'Unauthorized()' → 0x82b42900
    bytes4 constant EXPECTED_REVERT_SELECTOR = 0x82b42900;

    // =============== SETUP ==========================================

    function setUp() public {
        // Fork mainnet at the current head. For determinism, pin a block:
        //   vm.createSelectFork(RPC, 85600000);
        vm.createSelectFork(RPC);
    }

    // =============== TESTS ==========================================

    /// (a) Initial state: verify the on-chain precondition that enables the bug
    function test_InitialState_MatchesAssumption() public view {
        // Example: verify a role is NOT held, an allowance is 0, a pause is off
        // Replace with your precondition check.
        assertTrue(true, "initial state matches bug precondition");
    }

    /// (b) Exploit step: the user calls the target function
    /// (c) Resulting impact: observe the revert / incorrect state change
    function test_BugReproduces() public {
        // Fund the user with whatever tokens they need
        deal(TEST_TOKEN, user, 1_000_000);

        // Perform any prerequisite approvals
        vm.prank(user);
        IERC20Like(TEST_TOKEN).approve(TARGET, type(uint256).max);

        // Expect the exact revert signature
        vm.prank(user);
        vm.expectRevert(EXPECTED_REVERT_SELECTOR);
        ITarget(TARGET).vulnerableFunction(TEST_TOKEN, user, 1_000_000);
    }

    /// Control: if the bug was fixed (e.g., role granted, flag set), the same
    /// call should succeed. This test SHOULD FAIL in current state — that's
    /// the proof the bug exists. Or it's a positive control for post-fix.
    function test_Control_WouldPassAfterFix() public {
        // Use vm.prank of an authorised address to bypass the gating
        // condition, demonstrating the call works when the precondition is
        // satisfied. This proves the bug is specifically in the precondition.
        assertTrue(true, "skip this if you don't need a control");
    }

    // =============== HELPERS (if any) ===============================

    function _someHelper() internal pure returns (uint256) {
        return 42;
    }
}
