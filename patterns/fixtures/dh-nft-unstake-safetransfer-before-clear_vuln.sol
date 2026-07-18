// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface INft {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

contract NftStakeVuln {
    struct Slot { address owner; uint256 tokenId; uint256 amount; bool active; }
    mapping(uint256 => Slot) public slots;
    INft public nft;

    function depositNbl(uint256 index, uint256 amount) external {
        require(slots[index].active, "inactive");
        slots[index].amount += amount;
    }

    // Vuln: safeTransferFrom fires onERC721Received BEFORE the slot is cleared.
    function withdrawNft(uint256 index) external {
        Slot storage s = slots[index];
        require(s.owner == msg.sender, "owner");
        nft.safeTransferFrom(address(this), msg.sender, s.tokenId);
        s.active = false;
        s.owner = address(0);
    }
}
