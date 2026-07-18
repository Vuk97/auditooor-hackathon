// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC721 {
    function safeTransferFrom(address,address,uint256) external;
    function approve(address,uint256) external;
}

contract EscrowReturnVuln {
    IERC721 public nft;
    function returnNft(address owner, uint256 tokenId) external {
        nft.safeTransferFrom(address(this), owner, tokenId);
    }
}
