// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract FoTVuln {
    IERC20 public immutable token;
    mapping(address => uint256) public balances;

    constructor(address t) { token = IERC20(t); }

    // Detector MUST fire: transferFrom result used directly in accounting,
    // no pre/post balanceOf(address(this)) measurement.
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
    }
}
