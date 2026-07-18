// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like { function transfer(address, uint256) external returns (bool); }

abstract contract Guard {
    uint256 private _s = 1;
    modifier nonReentrant() { require(_s != 2); _s = 2; _; _s = 1; }
}

contract ReentrancyDrainClean is Guard {
    mapping(address => uint256) public balances;
    IERC20Like public token;

    // CLEAN: CEI order — storage deducted first, transfer last.
    function withdraw(uint256 amt) external {
        balances[msg.sender] -= amt;
        token.transfer(msg.sender, amt);
    }

    // CLEAN: nonReentrant guard present even though order is reversed.
    function claim(uint256 amt) external nonReentrant {
        token.transfer(msg.sender, amt);
        balances[msg.sender] -= amt;
    }
}
