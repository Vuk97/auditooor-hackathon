// SPDX-License-Identifier: MIT
// Fixture: unsafe-downcast-uint-truncation — CLEAN
pragma solidity ^0.8.20;

library SafeCast {
    function toUint96(uint256 v) internal pure returns (uint96) { require(v <= type(uint96).max); return uint96(v); }
    function toUint128(uint256 v) internal pure returns (uint128) { require(v <= type(uint128).max); return uint128(v); }
    function toUint64(uint256 v) internal pure returns (uint64) { require(v <= type(uint64).max); return uint64(v); }
}

contract DowncastClean {
    using SafeCast for uint256;
    mapping(address => uint96) public votes;
    mapping(address => uint128) public staked;
    uint64 public proposalETA;

    // CLEAN: SafeCast.toUint96 reverts on overflow.
    function delegateMint(address to, uint256 amount) external {
        votes[to] = amount.toUint96();
    }

    function recordStake(uint256 amount) external {
        staked[msg.sender] = amount.toUint128();
    }

    function scheduleProposal(uint256 eta) external {
        proposalETA = eta.toUint64();
    }
}
