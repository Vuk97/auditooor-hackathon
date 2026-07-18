// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// erc721-unsafe-transfer-to-contract detector. DO NOT DEPLOY.
///
/// `withdrawNft` routes an NFT to a caller-controlled `to` via raw
/// `IERC721(token).transferFrom(...)`. If `to` is a contract without
/// `onERC721Received`, the NFT arrives and is permanently locked.

interface IERC721 {
    function transferFrom(address from, address to, uint256 tokenId) external;
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

contract Erc721UnsafeTransferVuln {
    mapping(address => mapping(uint256 => bool)) public deposited;

    function deposit(IERC721 token, uint256 tokenId) external {
        token.transferFrom(msg.sender, address(this), tokenId);
        deposited[address(token)][tokenId] = true;
    }

    // VULNERABLE: uses IERC721(token).transferFrom to send the NFT out to
    // an arbitrary `to`. Matches the first alternative of the
    // body_contains_regex and does NOT contain safeTransferFrom.
    function withdrawNft(IERC721 token, address to, uint256 tokenId) external {
        require(deposited[address(token)][tokenId], "not deposited");
        deposited[address(token)][tokenId] = false;
        IERC721(token).transferFrom(address(this), to, tokenId);
    }
}
