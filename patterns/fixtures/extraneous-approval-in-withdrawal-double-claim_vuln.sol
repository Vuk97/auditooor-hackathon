// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract ExtraneousApprovalInWithdrawalDoubleClaimVuln {
    IERC20 public token;
    mapping(address => uint256) public allocation;

    function setAlloc(address u, uint256 a) external { allocation[u] = a; }

    function withdraw() external {
        uint256 amount = allocation[msg.sender];
        allocation[msg.sender] = 0;
        // VULN: both transfer AND approve — user can pull again.
        token.transfer(msg.sender, amount);
        token.approve(msg.sender, amount);
    }
}
