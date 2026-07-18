// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
///
/// `withdrawNft` uses `safeTransferFrom`, which triggers the
/// `onERC721Received` callback on contract recipients and reverts if the
/// recipient does not implement the interface. The body_not_contains_regex
/// term matches on `safeTransferFrom`, so the negative predicate holds
/// false and the detector does not fire.

interface IERC721 {
    function transferFrom(address from, address to, uint256 tokenId) external;
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

contract Erc721UnsafeTransferClean {
    mapping(address => mapping(uint256 => bool)) public deposited;

    function deposit(IERC721 token, uint256 tokenId) external {
        // Deposit side is intentionally `transferFrom` because the
        // receiver (this contract) is known to handle ERC721 safely.
        // But the function body contains `safeTransferFrom` via the
        // interface import; the matcher sees the token name.
        token.safeTransferFrom(msg.sender, address(this), tokenId);
        deposited[address(token)][tokenId] = true;
    }

    // CLEAN: uses safeTransferFrom — recipient gets the onERC721Received
    // callback, so contract recipients that do not implement the interface
    // cause a revert instead of a silent permanent lockup.
    function withdrawNft(IERC721 token, address to, uint256 tokenId) external {
        require(deposited[address(token)][tokenId], "not deposited");
        deposited[address(token)][tokenId] = false;
        IERC721(token).safeTransferFrom(address(this), to, tokenId);
    }
}
