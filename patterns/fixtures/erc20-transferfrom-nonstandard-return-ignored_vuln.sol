// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract PullVuln {
    IERC20 public token;
    mapping(address => uint256) public shares;

    // VULN: return value of transferFrom ignored. Non-reverting tokens
    // that return false silently skip the pull; user still gets credited.
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += amount;
    }
}
