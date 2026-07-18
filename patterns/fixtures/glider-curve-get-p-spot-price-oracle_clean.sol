// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ICurvePoolLike {
    function get_p(uint256 i) external view returns (uint256);
    function price_oracle(uint256 i) external view returns (uint256);
}

interface IChainlinkLite {
    function getAssetPrice(address asset) external view returns (uint256);
}

contract SUSDePriceProviderClean {
    ICurvePoolLike public immutable FRAX_POOL;
    IChainlinkLite public immutable uwuOracle;
    address public constant FRAX = 0x853d955aCEf822Db058eb8505911ED77F175b99e;
    uint256 public constant sUSDeScalingFactor = 1001;

    constructor(ICurvePoolLike pool, IChainlinkLite oracle) {
        FRAX_POOL = pool;
        uwuOracle = oracle;
    }

    // CLEAN: uses Curve's EMA `price_oracle(i)` instead of the flash-loan
    // manipulable `get_p(i)`. The EMA dampens single-block attacks, and we
    // still cross with a Chainlink reading below.
    function getPrice() external view returns (uint256) {
        uint256 fraxUsd = uwuOracle.getAssetPrice(FRAX);
        uint256 usdeFraxEma = FRAX_POOL.price_oracle(0);
        uint256 priceViaEma = (usdeFraxEma * fraxUsd) / 1e18;
        return (priceViaEma * sUSDeScalingFactor) / 1e3;
    }
}
