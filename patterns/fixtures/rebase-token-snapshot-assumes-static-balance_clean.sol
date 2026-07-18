// SPDX-License-Identifier: MIT
// Fixture: rebase-token-snapshot-assumes-static-balance — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

interface IAToken {
    function balanceOf(address) external view returns (uint256);
    function scaledBalanceOf(address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
}

interface IPool {
    function getReserveNormalizedIncome(address) external view returns (uint256);
}

contract ScaledAaveVault {
    IAToken public aToken;
    IPool public pool;
    address public underlying;
    // CLEAN: tracks principal (scaled) balance, not raw balanceOf.
    mapping(address => uint256) public principal;
    uint256 public totalPrincipal;

    uint256 private constant RAY = 1e27;

    // CLEAN: deposits record the SCALED balance delta, immune to rebase.
    // No `aToken.balanceOf(...)` snapshot into storage.
    function deposit(uint256 amount) external {
        uint256 beforeScaled = aToken.scaledBalanceOf(address(this));
        aToken.transferFrom(msg.sender, address(this), amount);
        uint256 afterScaled = aToken.scaledBalanceOf(address(this));
        uint256 delta = afterScaled - beforeScaled;
        principal[msg.sender] += delta;     // writes `principal`
        totalPrincipal += delta;
    }

    // Read path converts principal via normalized income on demand.
    function balanceOfUser(address user) external view returns (uint256) {
        uint256 idx = pool.getReserveNormalizedIncome(underlying);
        return (principal[user] * idx) / RAY;
    }
}
