// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like { function transfer(address, uint256) external returns (bool); }

abstract contract Guard {
    uint256 private _s = 1;
    modifier nonReentrant() { require(_s != 2); _s = 2; _; _s = 1; }
}

// SKILL_ISSUES #102 test-inverse-cei — CLEAN fixture.
// Either there is no pre-call state write (strict CEI with write after), OR
// the function carries a nonReentrant modifier.
contract TestInverseCEIClean is Guard {
    mapping(address => uint256) public deposits;
    IERC20Like public token;

    // CLEAN-1: write happens AFTER the external call → no pre-call mutation.
    function withdrawPostCall(uint256 amt) external {
        token.transfer(msg.sender, amt);
        deposits[msg.sender] -= amt;
    }

    // CLEAN-2: pre-call mutation present, but nonReentrant guard suppresses it.
    function withdrawGuarded(uint256 amt) external nonReentrant {
        deposits[msg.sender] -= amt;
        token.transfer(msg.sender, amt);
    }
}
