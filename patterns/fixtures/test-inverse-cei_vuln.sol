// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like { function transfer(address, uint256) external returns (bool); }

// SKILL_ISSUES #102 test-inverse-cei — VULN fixture.
// State write happens BEFORE the external call with no reentrancy guard.
// The callee may be malicious; attacker re-enters while the optimistic write
// is observable but the final transfer has not yet been executed.
contract TestInverseCEIVuln {
    mapping(address => uint256) public deposits;
    IERC20Like public token;

    function withdraw(uint256 amt) external {
        // State mutation FIRST (pre-external-call) — inverse CEI.
        deposits[msg.sender] -= amt;
        // External call AFTER the state write, no guard.
        token.transfer(msg.sender, amt);
    }
}
