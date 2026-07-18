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

contract CleanHook is BaseHook {
    error SlippageExceeded();

    /// CLEAN: returns non-zero BeforeSwapDelta but explicitly enforces
    /// user slippage (sqrtPriceLimitX96 + minOut) before returning.
    function _beforeSwap(address, PoolKey calldata key, SwapParams calldata params, bytes calldata data)
        internal
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        uint256 minOut = abi.decode(data, (uint256));
        int128 unspec = _swap(key, params, minOut);
        // enforce sqrtPriceLimitX96 user guard
        if (params.sqrtPriceLimitX96 == 0) revert SlippageExceeded();
        BeforeSwapDelta delta = toBeforeSwapDelta(int128(-int256(params.amountSpecified)), unspec);
        return (this.beforeSwap.selector, delta, 0);
    }

    function _swap(PoolKey calldata, SwapParams calldata p, uint256 minOut) internal pure returns (int128) {
        int128 r = int128(p.amountSpecified > 0 ? int256(1) : int256(-1));
        if (uint128(r > 0 ? r : -r) < minOut) revert SlippageExceeded();
        return r;
    }
}
