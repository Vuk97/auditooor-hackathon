// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract StaleBalanceCacheOverExternalCallLoopClean {
    IERC20 public token;
    address[] public strategies;

    function distribute() external {
        // CLEAN: compute all shares first against one snapshot, then refresh at transfer.
        uint256 total = token.balanceOf(address(this));
        uint256 share = total / strategies.length;
        for (uint256 i = 0; i < strategies.length; i++) {
            uint256 available = token.balanceOf(address(this));
            uint256 amount = share < available ? share : available;
            token.transfer(strategies[i], amount);
        }
    }
}
