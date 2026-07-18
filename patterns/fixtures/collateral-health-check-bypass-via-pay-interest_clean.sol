// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CollateralHealthCheckBypassViaPayInterestClean {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    function _requireHealthy(address u) internal view {
        require(collateral[u] * 85 / 100 >= debt[u], "unsafe");
    }

    function borrow(uint256 amount) external {
        debt[msg.sender] += amount;
        _requireHealthy(msg.sender);
    }

    function payInterest(uint256 fromCollateral) external {
        collateral[msg.sender] -= fromCollateral;
        _requireHealthy(msg.sender);
    }
}
