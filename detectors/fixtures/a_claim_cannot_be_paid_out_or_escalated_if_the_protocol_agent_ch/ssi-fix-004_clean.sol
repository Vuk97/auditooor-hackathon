// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ClaimAgentChangeClean {
    address public protocolAgent;
    mapping(uint256 => address) public payoutClaimAgent;
    mapping(uint256 => bool) public claimPaid;

    constructor(address initialAgent) {
        protocolAgent = initialAgent;
    }

    function openClaim(uint256 claimId) external {
        payoutClaimAgent[claimId] = protocolAgent;
    }

    function rotateProtocolAgent(address nextAgent) external {
        protocolAgent = nextAgent;
    }

    function payoutClaim(uint256 claimId) external returns (bool) {
        _syncClaimAgent(claimId);
        require(msg.sender == payoutClaimAgent[claimId], "current claim agent");
        claimPaid[claimId] = true;
        return claimPaid[claimId];
    }

    function _syncClaimAgent(uint256 claimId) internal {
        payoutClaimAgent[claimId] = protocolAgent;
    }
}
