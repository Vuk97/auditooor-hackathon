// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC721 {
    function getApproved(uint256) external view returns (address);
    function ownerOf(uint256) external view returns (address);
}

contract NFTEscrowVuln {
    IERC721 public nft;
    mapping(uint256 => address) public escrowOwner;

    /// VULN: relies only on getApproved without checking ownerOf.
    function stake(uint256 tokenId) external {
        require(nft.getApproved(tokenId) == msg.sender, "not approved");
        escrowOwner[tokenId] = msg.sender;
    }
}
