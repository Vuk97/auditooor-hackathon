// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IToken {
    function getPastTotalSupply(uint256 timepoint) external view returns (uint256);
}

contract GovernorClean {
    IToken public token;
    uint256 public pct = 4;
    function quorum(uint256 timepoint) external view returns (uint256) {
        return token.getPastTotalSupply(timepoint) * pct / 100;
    }
}
