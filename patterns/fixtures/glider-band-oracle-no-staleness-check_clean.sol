// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IStdReference {
    struct ReferenceData { uint256 rate; uint256 lastUpdatedBase; uint256 lastUpdatedQuote; }
    function getReferenceData(string memory base, string memory quote) external view returns (ReferenceData memory);
}

contract BandClean {
    IStdReference public bandOracle;
    uint256 public constant MAX_STALE = 60;
    constructor(IStdReference r) { bandOracle = r; }

    function price() external view returns (uint256) {
        IStdReference.ReferenceData memory d = bandOracle.getReferenceData("ETH", "USD");
        require(d.rate > 0, "zero rate");
        require(block.timestamp - d.lastUpdatedBase <= MAX_STALE, "stale base");
        require(block.timestamp - d.lastUpdatedQuote <= MAX_STALE, "stale quote");
        return d.rate;
    }
}
