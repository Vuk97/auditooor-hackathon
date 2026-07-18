// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Severity: High
// ANTI-PATTERN: role separation + withheld-artifact assertion present,
// but the harness does not assert that the protocol finalized or settled.
// Rule 44 should emit fail-no-attack-causality-assertion.

import "forge-std/Test.sol";

contract MissingCausalityTest is Test {
    // Role separation: distinct actors.
    address attacker = makeAddr("attacker");
    address victim   = makeAddr("victim");

    function test_OpposedTrace_NoCausality() public {
        // This is an opposed-trace harness: attacker withholds victim approval.

        // Withheld-artifact assertion: no prior legitimate withdrawal.
        assertFalse(false, "no legitimate withdrawal auth in window");

        // Attacker calls the protocol under test.
        vm.startPrank(attacker);
        // do the attack...
        vm.stopPrank();

        // MISSING: no state assertion whatsoever.
        // (intentionally omitted for Rule 44 test)
    }
}
