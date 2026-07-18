// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ZeroLockerMergeVotingPowerClean {
    mapping(uint256 => uint256) internal balanceOfNFT;
    uint256 internal mergedTotal;

    constructor() {
        balanceOfNFT[1] = 100 ether;
        balanceOfNFT[2] = 1 ether;
    }

    function merge(uint256 fromTokenId, uint256 toTokenId) external returns (uint256) {
        _refreshVotingPower(fromTokenId);
        _refreshVotingPower(toTokenId);

        uint256 sourcePower = balanceOfNFT[fromTokenId];
        uint256 targetPower = balanceOfNFT[toTokenId];

        balanceOfNFT[toTokenId] = targetPower + sourcePower;
        delete balanceOfNFT[fromTokenId];
        mergedTotal += sourcePower;

        return balanceOfNFT[toTokenId];
    }

    function _refreshVotingPower(uint256 subject) internal {
        require(subject != 0, "missing token");
    }
}
