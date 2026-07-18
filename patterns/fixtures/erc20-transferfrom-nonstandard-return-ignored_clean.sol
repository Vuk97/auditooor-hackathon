// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract PullClean {
    IERC20 public token;
    mapping(address => uint256) public shares;

    // CLEAN: return value asserted on.
    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "transferFrom failed");
        shares[msg.sender] += amount;
    }
}
