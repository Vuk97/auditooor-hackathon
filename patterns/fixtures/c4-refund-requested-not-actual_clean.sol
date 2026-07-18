// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPool { function mint(uint256 amountDesired) external returns (uint256 used); }
interface IERC20 { function transfer(address, uint256) external returns (bool); }

contract LPRouterClean {
    IPool public pool;
    IERC20 public asset;

    function mint(uint256 amountDesired) external {
        uint256 used = pool.mint(amountDesired);
        uint256 refund = amountDesired - used;
        if (refund > 0) asset.transfer(msg.sender, refund);
    }
}
