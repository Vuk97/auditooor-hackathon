// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IStdReference {
    struct ReferenceData { uint256 rate; uint256 lastUpdatedBase; uint256 lastUpdatedQuote; }
    function getReferenceData(string memory base, string memory quote) external view returns (ReferenceData memory);
}

contract BandVuln {
    IStdReference public bandOracle;
    constructor(IStdReference r) { bandOracle = r; }

    function price() external view returns (uint256) {
        IStdReference.ReferenceData memory d = bandOracle.getReferenceData("ETH", "USD");
        return d.rate;
    }
}
