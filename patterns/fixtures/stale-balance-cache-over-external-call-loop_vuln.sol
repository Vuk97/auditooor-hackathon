// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract StaleBalanceCacheOverExternalCallLoopVuln {
    IERC20 public token;
    address[] public strategies;

    function distribute() external {
        // VULN: total cached once, then looped external transfers reduce real balance.
        uint256 total = token.balanceOf(address(this));
        uint256 share = total / strategies.length;
        for (uint256 i = 0; i < strategies.length; i++) {
            token.transfer(strategies[i], share);
        }
    }
}
