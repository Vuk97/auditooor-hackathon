// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function balanceOf(address) external view returns (uint256); }

contract Vault4626Clean {
    IERC20 public lp;
    uint256 public cachedPriceTwap; // updated via keeper w/ block delay
    uint256 public lastTwapUpdate;

    function totalAssets() external view returns (uint256) {
        uint256 bal = lp.balanceOf(address(this));
        return (bal * cachedPriceTwap) / 1e18;
    }
}
