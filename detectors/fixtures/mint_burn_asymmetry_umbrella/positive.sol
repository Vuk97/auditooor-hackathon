// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// positive.sol - mint-burn-asymmetry-umbrella
// VULN: burn decreases balanceOf but does NOT decrease totalSupply.
// Mint+burn cycle inflates totalSupply indefinitely.

contract VulnMintBurnAsymmetry {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    // CLEAN mint: correctly increments both balance and totalSupply
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    // VULN burn: decrements balance but FORGETS to decrement totalSupply
    // After burn, totalSupply > sum(balanceOf) - inflated supply
    function burn(address account, uint256 amount) external {
        require(balanceOf[account] >= amount, "insufficient balance");
        balanceOf[account] -= amount;
        // BUG: totalSupply -= amount; is MISSING here
        // Any downstream system using totalSupply (e.g. ERC4626 share price) gets inflated values
    }

    // share price computed on inflated totalSupply
    function sharePrice(uint256 totalAssets) external view returns (uint256) {
        if (totalSupply == 0) return 1e18;
        return totalAssets * 1e18 / totalSupply; // VULN: totalSupply is inflated
    }
}
