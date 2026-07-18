// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ICurvePoolLike {
    function get_p(uint256 i) external view returns (uint256);
    function price_oracle(uint256 i) external view returns (uint256);
}

interface IChainlinkLite {
    function getAssetPrice(address asset) external view returns (uint256);
}

contract SUSDePriceProviderBUniCatchVuln {
    ICurvePoolLike public immutable FRAX_POOL;
    IChainlinkLite public immutable uwuOracle;
    address public constant FRAX = 0x853d955aCEf822Db058eb8505911ED77F175b99e;
    uint256 public constant sUSDeScalingFactor = 1001;

    constructor(ICurvePoolLike pool, IChainlinkLite oracle) {
        FRAX_POOL = pool;
        uwuOracle = oracle;
    }

    // VULN: computes a "price" that directly includes Curve's get_p() spot read.
    // Flash-loan manipulation of FRAX_POOL reserves within a single tx shifts
    // the result, enabling collateral over-borrow.
    function getPrice() external view returns (uint256) {
        uint256 fraxUsd = uwuOracle.getAssetPrice(FRAX);
        // get_p spot read — manipulable.
        uint256 usdeFraxSpot = FRAX_POOL.get_p(0);
        uint256 priceViaSpot = (usdeFraxSpot * fraxUsd) / 1e18;
        return (priceViaSpot * sUSDeScalingFactor) / 1e3;
    }
}
