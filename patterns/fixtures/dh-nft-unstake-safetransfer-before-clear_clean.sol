// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface INftC {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

contract NftStakeClean {
    struct Slot { address owner; uint256 tokenId; uint256 amount; bool active; }
    mapping(uint256 => Slot) public slots;
    INftC public nft;
    bool private _locked;

    modifier nonReentrant() { require(!_locked, "RE"); _locked = true; _; _locked = false; }

    function depositNbl(uint256 index, uint256 amount) external nonReentrant {
        require(slots[index].active, "inactive");
        slots[index].amount += amount;
    }

    // Clean: nonReentrant, AND state cleared BEFORE external callback.
    function withdrawNft(uint256 index) external nonReentrant {
        Slot storage s = slots[index];
        require(s.owner == msg.sender, "owner");
        uint256 tokenId = s.tokenId;
        delete slots[index];
        nft.safeTransferFrom(address(this), msg.sender, tokenId);
    }
}
