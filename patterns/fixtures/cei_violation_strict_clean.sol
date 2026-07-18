// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like { function transfer(address, uint256) external returns (bool); }

abstract contract Guard {
    uint256 private _s = 1;
    modifier nonReentrant() { require(_s != 2); _s = 2; _; _s = 1; }
}

contract CEICleanStrict is Guard {
    mapping(address => uint256) public balances;
    IERC20Like public token;

    // CLEAN: state write FIRST, then external call (CEI)
    function withdrawCEI(uint256 amt) external {
        balances[msg.sender] -= amt;
        token.transfer(msg.sender, amt);
    }

    // CLEAN: nonReentrant modifier present
    function withdrawGuarded(uint256 amt) external nonReentrant {
        token.transfer(msg.sender, amt);
        balances[msg.sender] -= amt;
    }
}
