// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library LPercentage {
    function validatePercent(uint256 percent) internal pure returns (bool) {
        return percent <= 100;
    }
}

contract GoatVotingClean {
    struct Vote {
        address challenger;
        uint256 voterPercent;
    }

    mapping(address => Vote) public activeVoteByDefender;
    mapping(address => bool) public hasActiveVote;

    function createVote(address defender, uint256 voterPercent_) external {
        require(defender != address(0), "defender");
        require(!hasActiveVote[defender], "vote exists");
        require(voterPercent_ > 0, "zero percent");
        require(LPercentage.validatePercent(voterPercent_), "bad percent");

        activeVoteByDefender[defender] = Vote({
            challenger: msg.sender,
            voterPercent: voterPercent_
        });
        hasActiveVote[defender] = true;
    }
}
