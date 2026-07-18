// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library Math {
    enum Rounding { Down, Up }
    function mulDiv(uint256 a, uint256 b, uint256 d, Rounding) internal pure returns (uint256) {
        return a * b / d;
    }
}

contract VaultVuln {
    using Math for uint256;
    uint256 public totalAssets;
    uint256 public totalSupply;
    function previewRedeem(uint256 shares) external view returns (uint256) {
        // VULN: spec says Rounding.Down
        return Math.mulDiv(shares, totalAssets, totalSupply, Math.Rounding.Up);
    }
}
