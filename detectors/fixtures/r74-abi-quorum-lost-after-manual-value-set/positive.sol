// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ManualQuorumGovernorPositive {
    address[] public members;
    uint256 public quorum;

    event QuorumSet(uint256 previousQuorum, uint256 newQuorum);

    constructor() {
        members.push(address(0x1));
        members.push(address(0x2));
        members.push(address(0x3));
        quorum = 2;
    }

    function setQuorum(uint256 newQuorum) external {
        uint256 previousQuorum = quorum;
        quorum = newQuorum;
        emit QuorumSet(previousQuorum, newQuorum);
    }
}
