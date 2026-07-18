// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like { function transfer(address, uint256) external returns (bool); }

contract ReentrancyDrainVuln {
    mapping(address => uint256) public balances;
    IERC20Like public token;

    // VULN: external transfer precedes the storage deduction, no nonReentrant guard.
    function withdraw(uint256 amt) external {
        token.transfer(msg.sender, amt);
        balances[msg.sender] -= amt;
    }

    // VULN: unstake variant with low-level ETH send before state update.
    function unstake(uint256 amt) external {
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] -= amt;
    }
}
