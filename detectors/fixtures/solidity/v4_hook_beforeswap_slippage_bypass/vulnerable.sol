// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

type BeforeSwapDelta is int256;

function toBeforeSwapDelta(int128 a, int128 b) pure returns (BeforeSwapDelta) {
    return BeforeSwapDelta.wrap((int256(a) << 128) | (int256(b) & type(uint128).max));
}

struct PoolKey {
    address currency0;
    address currency1;
    uint24 fee;
}

struct SwapParams {
    bool zeroForOne;
    int256 amountSpecified;
    uint160 sqrtPriceLimitX96;
}

interface IBaseHook {
    function beforeSwap(address sender, PoolKey calldata key, SwapParams calldata params, bytes calldata)
        external
        returns (bytes4, BeforeSwapDelta, uint24);
}

abstract contract BaseHook is IBaseHook {
    function beforeSwap(address sender, PoolKey calldata key, SwapParams calldata params, bytes calldata d)
        external
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        return _beforeSwap(sender, key, params, d);
    }

    function _beforeSwap(address sender, PoolKey calldata key, SwapParams calldata params, bytes calldata)
        internal
        virtual
        returns (bytes4, BeforeSwapDelta, uint24);
}

contract VulnerableHook is BaseHook {
    /// VULN: returns non-zero BeforeSwapDelta, prices internally,
    /// no consumption of params.sqrtPriceLimitX96 / minOut anywhere
    /// in the contract.
    function _beforeSwap(address, PoolKey calldata key, SwapParams calldata params, bytes calldata)
        internal
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        int128 unspec = _swap(key, params);
        BeforeSwapDelta delta = toBeforeSwapDelta(int128(-int256(params.amountSpecified)), unspec);
        return (this.beforeSwap.selector, delta, 0);
    }

    function _swap(PoolKey calldata, SwapParams calldata p) internal pure returns (int128) {
        // pricing math without any slippage check
        return int128(p.amountSpecified > 0 ? int256(1) : int256(-1));
    }
}
