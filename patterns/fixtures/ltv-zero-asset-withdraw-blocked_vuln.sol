// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// ltv-zero-asset-withdraw-blocked detector. DO NOT DEPLOY.
///
/// A Morpho-Aave-style lending integrator that recomputes health factor
/// locally from `reserveConfig.ltv`. When governance turns off an asset
/// as collateral (ltv -> 0), `withdraw`, `borrow` and `liquidate` either
/// divide by zero or evaluate `collateral * 0` and force solvent users
/// into a `require(hf > 1e18)` that can never pass.
///
/// This reproduces the Solodit C0006 finding shape.

interface ILendingPool {
    struct ReserveConfigurationMap { uint256 data; }
    struct ReserveData {
        ReserveConfigurationMap configuration;
        uint128 liquidityIndex;
    }
    function getReserveData(address asset) external view returns (ReserveData memory);
}

contract LtvZeroAssetWithdrawBlockedVuln {
    // Satisfies the contract-level precondition `pool|aave|comet|lendingPool|assetConfig`.
    ILendingPool public pool;
    address public aave;
    mapping(address => uint256) public userCollateral;
    mapping(address => uint256) public userDebt;

    constructor(ILendingPool _pool, address _aave) {
        pool = _pool;
        aave = _aave;
    }

    // Required by the contract-level precondition
    // `healthFactor|calcHF|_computeHF|healthCheck`.
    function healthFactor(address user, address asset) public view returns (uint256) {
        ILendingPool.ReserveData memory d = pool.getReserveData(asset);
        uint256 ltv = d.configuration.data & 0xffff; // Aave v3 lower-16 bitmask
        uint256 coll = userCollateral[user];
        uint256 debt = userDebt[user];
        if (debt == 0) return type(uint256).max;
        // VULN: when ltv == 0 this returns 0 and every hf check below fails.
        // No guard branch on ltv == 0 → withdraw of 'pure' supply is blocked.
        return (coll * ltv * 1e18) / (debt * 10000);
    }

    // VULNERABLE: withdraw. Reads LTV (via reserveConfig / getReserveData)
    // and checks HF > 1e18. When LTV=0, `healthFactor` returns 0 and the
    // require reverts even for users with zero debt on this specific
    // asset. Matches function.name_matches `withdraw`, positive
    // body_contains_regex `ltv|reserveConfig|getReserveData`, and does
    // NOT contain any `ltv == 0` / `ltv != 0` / `ltv > 0` guard.
    function withdraw(address asset, uint256 amount) external {
        ILendingPool.ReserveData memory d = pool.getReserveData(asset);
        uint256 ltv = d.configuration.data & 0xffff;
        uint256 coll = userCollateral[msg.sender];
        uint256 debt = userDebt[msg.sender];
        uint256 hf = (coll * ltv * 1e18) / (debt * 10000 + 1);
        require(hf >= 1e18, "unhealthy");
        userCollateral[msg.sender] = coll - amount;
    }

    // VULNERABLE: borrow. Same LTV-based gate, same missing zero guard.
    function borrow(address asset, uint256 amount) external {
        ILendingPool.ReserveData memory d = pool.getReserveData(asset);
        uint256 ltv = d.configuration.data & 0xffff;
        uint256 newDebt = userDebt[msg.sender] + amount;
        uint256 maxBorrow = (userCollateral[msg.sender] * ltv) / 10000;
        require(newDebt <= maxBorrow, "over LTV");
        userDebt[msg.sender] = newDebt;
    }

    // VULNERABLE: liquidate. Reads LTV, recomputes HF, never handles
    // LTV=0. Legitimate liquidations become impossible when governance
    // turns the asset off.
    function liquidate(address user, address asset, uint256 repay) external {
        ILendingPool.ReserveData memory d = pool.getReserveData(asset);
        uint256 ltv = d.configuration.data & 0xffff;
        uint256 hf = (userCollateral[user] * ltv * 1e18) / (userDebt[user] * 10000 + 1);
        require(hf < 1e18, "not liquidatable");
        userDebt[user] -= repay;
    }
}
