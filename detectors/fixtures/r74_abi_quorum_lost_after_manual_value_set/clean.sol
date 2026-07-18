// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ManualQuorumGovernorClean {
    uint256 internal constant MIN_QUORUM_BPS = 5_100;

    address[] public members;
    uint256 public quorum;

    event QuorumSet(uint256 previousQuorum, uint256 newQuorum);

    constructor() {
        members.push(address(0x1));
        members.push(address(0x2));
        members.push(address(0x3));
        members.push(address(0x4));
        quorum = 3;
    }

    function setQuorum(uint256 newQuorum) external {
        _validateQuorumBounds(newQuorum);
        uint256 previousQuorum = quorum;
        quorum = newQuorum;
        emit QuorumSet(previousQuorum, newQuorum);
    }

    function _validateQuorumBounds(uint256 newQuorum) internal view {
        require(
            newQuorum * 10_000 >= members.length * MIN_QUORUM_BPS,
            "quorum too low"
        );
    }
}
