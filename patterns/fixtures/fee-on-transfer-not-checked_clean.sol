// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract FoTClean {
    IERC20 public immutable token;
    mapping(address => uint256) public balances;

    constructor(address t) { token = IERC20(t); }

    // Detector MUST NOT fire: pre/post balanceOf(address(this)) delta is used
    // as the credited amount, tolerating fee-on-transfer tokens.
    function deposit(uint256 amount) external {
        uint256 beforeBal = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - beforeBal;
        balances[msg.sender] += received;
    }
}
