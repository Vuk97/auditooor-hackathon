// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
///
/// getPrice() derives the collateral price from a UniV3 TWAP via
/// OracleLibrary.consult over a protocol-appropriate window. slot0 is
/// never read as the authoritative price. The precondition still fires
/// on the contract (IUniswapV3Pool reference is present) but the
/// function-level negative guard (`\.observe\s*\(|OracleLibrary\.consult`)
/// filters out the TWAP-anchored function.

interface IUniswapV3Pool {
    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory tickCumulatives, uint160[] memory);
}

library OracleLibrary {
    function consult(address pool, uint32 secondsAgo)
        internal
        view
        returns (int24 arithmeticMeanTick, uint128)
    {
        uint32[] memory ago = new uint32[](2);
        ago[0] = secondsAgo;
        ago[1] = 0;
        (int56[] memory tickCumulatives, ) = IUniswapV3Pool(pool).observe(ago);
        int56 delta = tickCumulatives[1] - tickCumulatives[0];
        arithmeticMeanTick = int24(delta / int56(int32(secondsAgo)));
        return (arithmeticMeanTick, 0);
    }

    function getQuoteAtTick(int24, uint128 amount, address, address)
        internal
        pure
        returns (uint256)
    {
        return uint256(amount);
    }
}

contract SlotZeroOracleClean {
    address public pool;
    uint32 public constant TWAP_PERIOD = 1800; // 30 min

    constructor(address _pool) {
        pool = _pool;
    }

    /// CLEAN: TWAP via OracleLibrary.consult. Body contains "OracleLibrary.consult"
    /// so the body_not_contains_regex guard in the pattern blocks a match.
    function getPrice(uint128 baseAmount, address baseToken, address quoteToken)
        external
        view
        returns (uint256)
    {
        (int24 arithmeticMeanTick, ) = OracleLibrary.consult(pool, TWAP_PERIOD);
        return OracleLibrary.getQuoteAtTick(arithmeticMeanTick, baseAmount, baseToken, quoteToken);
    }
}
