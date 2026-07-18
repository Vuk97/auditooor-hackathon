// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Severity: High
// ANTI-PATTERN: single vm.startPrank(deployer) for all operations.
// Attacker and victim roles are not distinguished.
// This is the fail-no-role-separation shape Rule 44 catches.

import "forge-std/Test.sol";

contract SinglePrankTest is Test {
    address deployer = address(this);

    // No attacker/victim separation - same address for everything.
    // This violates Rule 44 role separation.

    function test_SinglePrankAllOperations() public {
        // All operations run under the same prank - no role separation.
        vm.startPrank(deployer);

        // deposit as deployer
        // withdraw as deployer (attacker == deployer == victim)
        // This is an opposed-trace harness but both sides use deployer.

        vm.stopPrank();
        // No withheld-artifact assertion loop.
        // No attack-causality state transition asserted.
    }
}
