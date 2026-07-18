// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultClean {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    uint256 public totalAssets;

    function _burn(address from, uint256 amount) internal {
        balanceOf[from] -= amount;
        totalSupply -= amount;
    }

    function previewRedeem(uint256 shares) public view returns (uint256) {
        return totalSupply == 0 ? 0 : (shares * totalAssets) / totalSupply;
    }

    // Clean: preview + minOut gate BEFORE any state mutation.
    function redeem(uint256 shares, uint256 minOut) external returns (uint256 out) {
        out = previewRedeem(shares);
        require(out >= minOut, "slippage");
        _burn(msg.sender, shares);
        totalAssets -= out;
    }
}
