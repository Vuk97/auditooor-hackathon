// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IToken {
    function totalSupply() external view returns (uint256);
    function getPastTotalSupply(uint256) external view returns (uint256);
}

contract GovernorVuln {
    IToken public token;
    uint256 public pct = 4; // 4%
    function quorum(uint256) external view returns (uint256) {
        // VULN: live totalSupply, not snapshot
        return token.totalSupply() * pct / 100;
    }
}
