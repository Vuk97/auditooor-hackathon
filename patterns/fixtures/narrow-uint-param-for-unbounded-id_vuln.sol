// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal stand-ins for OZ Counters + ERC721 surface.
library Counters {
    struct Counter { uint256 _value; }
    function current(Counter storage c) internal view returns (uint256) { return c._value; }
    function increment(Counter storage c) internal { unchecked { c._value += 1; } }
}

abstract contract ERC721Like {
    mapping(uint256 => address) internal _owners;
    function ownerOf(uint256 id) public view returns (address) { return _owners[id]; }
    function _mint(address to, uint256 id) internal { _owners[id] = to; }
}

contract FighterFarm is ERC721Like {
    using Counters for Counters.Counter;

    Counters.Counter private _tokenIdCounter;
    mapping(uint256 => uint8) public numRerolls;
    uint8 public constant MAX_REROLLS = 3;

    function mint(address to) external {
        uint256 id = _tokenIdCounter.current();
        _tokenIdCounter.increment();
        _mint(to, id);
    }

    // BUG: `uint8 tokenId` — once the ERC721 counter passes 255,
    // holders of tokens >= 256 can never call reRoll (ABI truncates
    // the id, which either reverts ownerOf or silently reRolls a
    // different token). Permanent, per-NFT DoS.
    function reRoll(uint8 tokenId, uint8 fighterType) external {
        require(msg.sender == ownerOf(tokenId), "not owner");
        require(numRerolls[tokenId] < MAX_REROLLS, "max rerolls");
        numRerolls[tokenId] += 1;
        // ... re-randomize traits for `tokenId` ...
    }
}
