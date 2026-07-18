// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 id) external;
}

contract NFTEscrowVuln {
    struct Listing { address seller; uint256 buyPrice; bool active; }
    mapping(uint256 => Listing) public listing;
    IERC721 public immutable nft;

    constructor(address _nft) { nft = IERC721(_nft); }

    function list(uint256 id, uint256 price) external {
        listing[id] = Listing(msg.sender, price, true);
        nft.safeTransferFrom(msg.sender, address(this), id);
    }

    // Detector MUST fire: claim path transfers NFT with no active-listing check.
    function claim(uint256 id) external {
        nft.safeTransferFrom(address(this), msg.sender, id);
    }
}
