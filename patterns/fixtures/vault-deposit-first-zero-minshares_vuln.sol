// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: vault deposit entrypoints accept a `minShares` / `minOut` slippage
// parameter but never enforce `minShares > 0`. Caller can pass zero and
// the nominal `shares >= minShares` guard degenerates into `shares >= 0`.
// First-depositor inflation / sandwich manipulation succeeds.

contract ZeroMinSharesVaultVuln {
    uint256 public totalShares;
    uint256 public totalAssets;
    mapping(address => uint256) public shareOf;

    // VULN 1: classic deposit with minShares param, no positivity check.
    function deposit(uint256 assets, uint256 minShares) external returns (uint256 shares) {
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

    // VULN 2: mint variant, same shape.
    function mint(uint256 assets, uint256 minShares) external returns (uint256 shares) {
        shares = assets * totalShares / totalAssets;
        require(shares > minShares, "slippage");
        shareOf[msg.sender] += shares;
        totalShares += shares;
        totalAssets += assets;
    }

    // VULN 3: depositForReceiver overload with `received >= minOut` form.
    function depositForReceiver(uint256 assets, uint256 minOut, address receiver)
        external
        returns (uint256 received)
    {
        received = assets * totalShares / totalAssets;
        require(received >= minOut, "slippage");
        shareOf[receiver] += received;
        totalShares += received;
        totalAssets += assets;
    }
}
