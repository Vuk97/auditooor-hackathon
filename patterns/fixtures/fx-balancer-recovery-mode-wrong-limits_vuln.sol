// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

// Fixture: vulnerable — recovery mode passes outer minAmountsOut to inner parent pool.
// Source: balancer/balancer-v3-monorepo@4034469 (CLR audit fix)

interface IVault {
    function isPoolInRecoveryMode(address pool) external view returns (bool);
    function removeLiquidityRecovery(address pool, address sender, uint256 maxBptIn,
                                      uint256[] memory minAmountsOut) external returns (uint256[] memory);
}

contract CompositeLiquidityRouterHooks {
    IVault internal _vault;

    struct Params {
        address pool;
        address sender;
        uint256 maxBptAmountIn;
        uint256[] minAmountsOut; // these are FINAL token limits, not parent pool token limits
    }

    // VULNERABLE: params.minAmountsOut (final token limits) used as parent pool limits
    function _removeParentLiquidity(Params memory params, uint256 numParentTokens)
        internal
        returns (uint256[] memory parentPoolAmountsOut)
    {
        if (_vault.isPoolInRecoveryMode(params.pool)) {
            // BUG: params.minAmountsOut belongs to final tokens, not parent pool tokens
            parentPoolAmountsOut = _vault.removeLiquidityRecovery(
                params.pool,
                params.sender,
                params.maxBptAmountIn,
                params.minAmountsOut // wrong limits applied here
            );
        }
    }
}
