// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: Same vote entrypoints, but every weight read goes through a
// recognised historical-snapshot primitive:
//   - getPriorVotes / getPastVotes (Compound / OZ Governor)
//   - snapshot / balanceOfAt (ERC20Snapshot)
//   - _getVotingPower / checkpoint (ve-token)
//   - votingPowerAt (ERC20Votes)
// The negative guard regex on the pattern sees any of these and
// suppresses the match.

interface IVotingToken {
    function balanceOf(address) external view returns (uint256);
    function getPriorVotes(address, uint256) external view returns (uint256);
    function getPastVotes(address, uint256) external view returns (uint256);
    function balanceOfAt(address, uint256) external view returns (uint256);
    function votingPowerAt(address, uint256) external view returns (uint256);
}

contract VoteSnapshotClean {
    IVotingToken public immutable token;

    mapping(uint256 => mapping(address => uint256)) public votes;
    mapping(address => address) public delegatee;
    mapping(uint256 => uint256) public proposalSnapshotBlock;
    mapping(uint256 => bool) public voting;
    mapping(address => uint256) public voter;
    mapping(bytes32 => uint256) public gauge;

    constructor(address _t) {
        token = IVotingToken(_t);
    }

    // CLEAN shape 1: getPastVotes at proposal snapshot block.
    // The body still reads balanceOf for a display-only comparison but
    // the vote weight itself derives from getPastVotes, so the negative
    // guard fires and the pattern does not flag.
    function vote(uint256 proposalId, bool support) external {
        uint256 snap = proposalSnapshotBlock[proposalId];
        uint256 weight = token.getPastVotes(msg.sender, snap);
        uint256 current = token.balanceOf(msg.sender); // sanity display
        if (support) votes[proposalId][msg.sender] = weight;
        require(current >= 0, "ok");
    }

    // CLEAN shape 2: ERC20Snapshot's balanceOfAt. The literal
    // "snapshot" appears in the body via balanceOfAt / a dedicated
    // snapshotId lookup — the negative regex matches "snapshot".
    mapping(uint256 => uint256) public snapshotIdOf;
    function castVote(uint256 proposalId) external {
        uint256 snapshotId = snapshotIdOf[proposalId];
        uint256 weight = token.balanceOfAt(msg.sender, snapshotId);
        votes[proposalId][msg.sender] = weight;
    }

    // CLEAN shape 3: ve-token internal voting-power helper.
    function _getVotingPower(address a, uint256 epoch) internal view returns (uint256) {
        return token.balanceOf(a) + epoch; // placeholder
    }
    function _castVote(uint256 proposalId, address v) external {
        uint256 weight = _getVotingPower(v, block.timestamp);
        uint256 fallbackRead = token.balanceOf(v); // not used for weight
        votes[proposalId][v] = weight;
        require(fallbackRead >= 0, "ok");
    }

    // CLEAN shape 4: OZ Votes votingPowerAt().
    function submitVote(uint256 proposalId) external {
        uint256 snap = proposalSnapshotBlock[proposalId];
        uint256 weight = token.votingPowerAt(msg.sender, snap);
        votes[proposalId][msg.sender] = weight;
    }
}
