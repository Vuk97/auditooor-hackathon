// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC721 {
    function getApproved(uint256) external view returns (address);
    function ownerOf(uint256) external view returns (address);
}

contract NFTEscrowClean {
    IERC721 public nft;
    mapping(uint256 => address) public escrowOwner;

    function stake(uint256 tokenId, address expectedOwner) external {
        require(nft.getApproved(tokenId) == msg.sender, "not approved");
        require(nft.ownerOf(tokenId) == expectedOwner, "owner mismatch");
        escrowOwner[tokenId] = msg.sender;
    }
}
