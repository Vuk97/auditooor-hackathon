// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
}

contract ExtraneousApprovalInWithdrawalDoubleClaimClean {
    IERC20 public token;
    mapping(address => uint256) public allocation;

    function setAlloc(address u, uint256 a) external { allocation[u] = a; }

    function withdraw() external {
        uint256 amount = allocation[msg.sender];
        allocation[msg.sender] = 0;
        // CLEAN: push only. No leftover approval.
        token.transfer(msg.sender, amount);
    }
}
