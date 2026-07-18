// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract ERC721AccessControlBase {
    mapping(bytes32 => mapping(address => bool)) internal _roles;

    function _grantRole(bytes32 role, address account) internal {
        _roles[role][account] = true;
    }

    function _revokeRole(bytes32 role, address account) internal {
        _roles[role][account] = false;
    }
}

contract StabilizerNFTAccessControlClean is ERC721AccessControlBase {
    bytes32 internal constant ESCROW_MANAGER_ROLE = keccak256("ESCROW_MANAGER_ROLE");

    mapping(uint256 => address) public ownerOf;
    mapping(uint256 => address) public escrowForToken;

    function initializePosition(uint256 tokenId, address minter, address escrow) external {
        ownerOf[tokenId] = minter;
        escrowForToken[tokenId] = escrow;
        _grantRole(ESCROW_MANAGER_ROLE, minter);
    }

    function _update(address from, address to, uint256 tokenId) internal {
        require(ownerOf[tokenId] == from, "not owner");
        _revokeRole(ESCROW_MANAGER_ROLE, from);
        _grantRole(ESCROW_MANAGER_ROLE, to);
        ownerOf[tokenId] = to;
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        _update(from, to, tokenId);
    }
}
