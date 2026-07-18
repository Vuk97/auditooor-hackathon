// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Correct variants: each computes the same kind of quantity but defends the
// round-to-zero direction, so the detector must NOT fire.
contract RoundToZeroDustBypassClean {
    uint256 public constant FEE_BPS = 30; // 0.30%
    uint256 public constant SCALE = 1e18;
    uint256 public collectedFees;
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public debt;
    mapping(address => uint256) public shares;

    // CLEAN: fee computed the same way but reverts when it floors to zero, so
    // dust inputs cannot bypass the charge.
    function transferWithFee(uint256 amount) external returns (uint256 out) {
        uint256 fee = amount * FEE_BPS / 10000;
        require(fee > 0, "dust");
        collectedFees += fee;
        out = amount - fee;
    }

    // CLEAN: interest rounds UP (Ceil) so dust principal still accrues a wei,
    // never silently to zero.
    function accrue(uint256 rate) external {
        uint256 interest = ceilDiv(debt[msg.sender] * rate, SCALE);
        debt[msg.sender] += interest;
    }

    // CLEAN: proceeds use a full-width mulDiv and revert on zero output, the
    // EIP-4626-correct shape this detector intentionally excludes.
    function redeem(uint256 shareAmount) external returns (uint256 assets) {
        assets = mulDivDown(shareAmount, totalAssets, totalSupply);
        require(assets > 0, "ZeroAssets");
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= assets;
    }

    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a + b - 1) / b;
    }

    function mulDivDown(uint256 a, uint256 b, uint256 d) internal pure returns (uint256) {
        return (a * b) / d;
    }
}
