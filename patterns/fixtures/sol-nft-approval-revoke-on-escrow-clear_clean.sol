// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC721 {
    function safeTransferFrom(address,address,uint256) external;
    function approve(address,uint256) external;
}

contract EscrowReturnClean {
    IERC721 public nft;
    function returnNft(address owner, uint256 tokenId) external {
        nft.approve(address(0), tokenId);
        nft.safeTransferFrom(address(this), owner, tokenId);
    }
}
