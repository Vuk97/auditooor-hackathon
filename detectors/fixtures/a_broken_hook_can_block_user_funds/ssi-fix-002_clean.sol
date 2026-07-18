// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBurnHook {
    function beforeBurn(address user, uint256 amount) external;
}

contract AlgebraLikePoolGuardedHookFixture {
    IBurnHook public burnHook;
    uint256 public pendingBurnLiquidity;
    bool public hookSynced;

    constructor(IBurnHook hook) {
        burnHook = hook;
        pendingBurnLiquidity = 100;
    }

    function burn(uint256 amount) external returns (bool) {
        _syncBurnHook();

        uint256 available = pendingBurnLiquidity;
        require(amount <= available, "too much");

        burnHook.beforeBurn(msg.sender, amount);

        pendingBurnLiquidity = available - amount;
        return true;
    }

    function _syncBurnHook() internal {
        hookSynced = true;
    }
}
