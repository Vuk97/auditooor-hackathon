// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20LikeGuarded {
    function safeTransferFrom(address from, address to, uint256 value) external;
}

contract DivisionRoundingToZeroWithTokenTransferClean {
    IERC20LikeGuarded public immutable token;
    uint256 public constant DECIMALS = 1e18;
    uint256 public rate = 10_000e18;
    mapping(address => uint256) public lpShares;

    constructor(IERC20LikeGuarded token_) {
        token = token_;
    }

    function deposit(uint256 rawAmount) external {
        uint256 transferAmount = (rawAmount * DECIMALS) / rate;
        require(transferAmount > 0, "dust transfer");
        token.safeTransferFrom(msg.sender, address(this), transferAmount);
        lpShares[msg.sender] += rawAmount;
    }
}
