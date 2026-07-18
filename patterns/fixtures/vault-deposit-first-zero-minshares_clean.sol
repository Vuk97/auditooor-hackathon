// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: every deposit entrypoint that accepts a min-output slippage
// parameter also enforces `minShares > 0` (or `minShares != 0`), so the
// nominal `shares >= minShares` guard cannot be disabled by passing zero.

contract PositiveMinSharesVaultClean {
    uint256 public totalShares;
    uint256 public totalAssets;
    mapping(address => uint256) public shareOf;

    // CLEAN 1: require(minShares > 0) enforces a non-zero slippage floor.
    function deposit(uint256 assets, uint256 minShares) external returns (uint256 shares) {
        require(minShares > 0, "min-shares zero");
        if (totalShares == 0) {
            shares = assets;
        } else {
            shares = assets * totalShares / totalAssets;
        }
        require(shares >= minShares, "slippage");
        shareOf[msg.sender] += shares;
        totalShares += shares;
        totalAssets += assets;
    }

    // CLEAN 2: require(minShares != 0) — equivalent idiom.
    function mint(uint256 assets, uint256 minShares) external returns (uint256 shares) {
        require(minShares != 0, "min-shares zero");
        shares = assets * totalShares / totalAssets;
        require(shares > minShares, "slippage");
        shareOf[msg.sender] += shares;
        totalShares += shares;
        totalAssets += assets;
    }

    // CLEAN 3: positivity check on minShares precedes the shares-vs-minShares guard.
    function depositForReceiver(uint256 assets, uint256 minShares, address receiver)
        external
        returns (uint256 shares)
    {
        require(minShares > 0, "min-shares zero");
        shares = assets * totalShares / totalAssets;
        require(shares >= minShares, "slippage");
        shareOf[receiver] += shares;
        totalShares += shares;
        totalAssets += assets;
    }
}
