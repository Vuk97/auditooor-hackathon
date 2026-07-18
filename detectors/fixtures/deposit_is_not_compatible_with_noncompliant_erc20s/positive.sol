// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract DepositNoncompliantErc20Positive {
    mapping(address => uint256) public deposited;
    uint256 public totalDeposited;

    function depositWithERC20(address token, uint256 amount) external {
        bool sent = IERC20(token).transferFrom(msg.sender, address(this), amount);
        require(sent, "erc20 transfer failed");

        deposited[msg.sender] += amount;
        totalDeposited += amount;
    }
}
