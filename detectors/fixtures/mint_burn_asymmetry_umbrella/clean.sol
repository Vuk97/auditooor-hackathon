// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// clean.sol - mint-burn-asymmetry-umbrella
// CLEAN: burn decreases both balanceOf AND totalSupply symmetrically.

contract CleanMintBurnSymmetric {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    // CLEAN mint: increments both balance and totalSupply
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    // CLEAN burn: decrements both balance AND totalSupply
    function burn(address account, uint256 amount) external {
        require(balanceOf[account] >= amount, "insufficient balance");
        balanceOf[account] -= amount;
        totalSupply -= amount; // CLEAN: symmetric with mint
    }

    function sharePrice(uint256 totalAssets) external view returns (uint256) {
        if (totalSupply == 0) return 1e18;
        return totalAssets * 1e18 / totalSupply; // CLEAN: totalSupply accurate
    }
}
