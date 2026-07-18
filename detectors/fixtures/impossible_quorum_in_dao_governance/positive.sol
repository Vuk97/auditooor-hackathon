// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ImpossibleQuorumGovernorPositive {
    uint256 internal totalsuppl;
    uint256 internal fixedNftVotingPower;

    function syncQuorumInputs() internal view returns (uint256) {
        return totalsuppl + fixedNftVotingPower;
    }

    function totalSupply() public view returns (uint256) {
        return totalsuppl + fixedNftVotingPower;
    }
}
