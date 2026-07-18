// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal Solidly/Velodrome-style gauge + bribe harness.
// VULN: `poke` and `updateBribe` are external and permissionless,
// and the update routine rewrites `bribe`, `reward`, and `lastUpdate`
// storage without snapshotting the outgoing voter's pending rewards.
// An adversary can call `poke(victim)` and retire the victim's
// accrued bribe distribution for the epoch.
contract BribeGriefVuln {
    mapping(uint256 => address) public voter;          // tokenId -> voter
    mapping(uint256 => uint256) public bribe;          // tokenId -> bribe balance
    mapping(uint256 => uint256) public reward;         // tokenId -> accrued reward
    mapping(uint256 => uint256) public lastUpdate;     // tokenId -> last update
    mapping(uint256 => uint256) public epoch;          // gauge -> current epoch
    address public gauge;

    // VULN: permissionless. Any caller can poke any voter. No onlyOwner,
    // onlyVoter, onlyGauge — no check that msg.sender == voter[tokenId].
    function poke(uint256 tokenId) external {
        // Overwrites bribe/reward/lastUpdate without preserving the prior
        // voter's pending share — classic C0263 griefing shape.
        bribe[tokenId] = bribe[tokenId] / 2;         // retire half
        reward[tokenId] = 0;                         // wipe pending reward
        lastUpdate[tokenId] = block.timestamp;
    }

    // VULN: same surface via updateBribe.
    function updateBribe(uint256 tokenId) external {
        bribe[tokenId] = 0;
        reward[tokenId] = 0;
        lastUpdate[tokenId] = block.timestamp;
    }

    // VULN: claimBribe permissionless and mutates bribe/reward storage.
    function claimBribe(uint256 tokenId) external {
        bribe[tokenId] = 0;
        reward[tokenId] = 0;
        lastUpdate[tokenId] = block.timestamp;
    }
}
