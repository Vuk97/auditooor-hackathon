// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: every bribe-mutating entry point sits behind an access modifier
// that the detector's negated `has_modifier` list matches. poke() is
// `onlyVoter` (only the voter-of-record for the tokenId may call);
// updateBribe is `onlyGauge`; claimBribe is `onlyOwner`. No
// permissionless surface — the griefing vector is closed.
abstract contract GaugeAuth {
    address public gauge;
    address public owner;
    mapping(uint256 => address) public voter;

    modifier onlyGauge() {
        require(msg.sender == gauge, "not-gauge");
        _;
    }
    modifier onlyOwner() {
        require(msg.sender == owner, "not-owner");
        _;
    }
    modifier onlyVoter(uint256 tokenId) {
        require(msg.sender == voter[tokenId], "not-voter");
        _;
    }
}

contract BribeGriefClean is GaugeAuth {
    mapping(uint256 => uint256) public bribe;
    mapping(uint256 => uint256) public reward;
    mapping(uint256 => uint256) public lastUpdate;
    mapping(uint256 => uint256) public epoch;

    // CLEAN: onlyVoter gate — caller MUST own the tokenId being poked.
    function poke(uint256 tokenId) external onlyVoter(tokenId) {
        bribe[tokenId] = bribe[tokenId] / 2;
        reward[tokenId] = 0;
        lastUpdate[tokenId] = block.timestamp;
    }

    // CLEAN: onlyGauge — the gauge contract coordinates updates.
    function updateBribe(uint256 tokenId) external onlyGauge {
        bribe[tokenId] = 0;
        reward[tokenId] = 0;
        lastUpdate[tokenId] = block.timestamp;
    }

    // CLEAN: onlyOwner on claim-shaped entry point.
    function claimBribe(uint256 tokenId) external onlyOwner {
        bribe[tokenId] = 0;
        reward[tokenId] = 0;
        lastUpdate[tokenId] = block.timestamp;
    }
}
