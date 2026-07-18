// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

// Fixture: fixed — zero limits passed to parent pool recovery; outer limits checked at end.
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
        uint256[] minAmountsOut; // these are FINAL token limits, checked after full unwrap
    }

    // FIXED: zero limits for parent pool; final limits enforced at end of full composite operation
    function _removeParentLiquidity(Params memory params, uint256 numParentTokens)
        internal
        returns (uint256[] memory parentPoolAmountsOut)
    {
        if (_vault.isPoolInRecoveryMode(params.pool)) {
            // Pass zero limits here; params.minAmountsOut is for final tokens checked at end
            parentPoolAmountsOut = _vault.removeLiquidityRecovery(
                params.pool,
                params.sender,
                params.maxBptAmountIn,
                new uint256[](numParentTokens) // zero limits for parent pool BPT unwrap
            );
            // Final minAmountsOut are checked after all child pool unwrapping completes
        }
    }
}
