// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ERC721Like {
    mapping(address => mapping(address => bool)) public isApprovedForAll;
    mapping(uint256 => address) public ownerOf;

    function _setApprovalForAll(address owner, address operator, bool approved) internal {
        isApprovedForAll[owner][operator] = approved;
    }
}

contract NFTMarket is ERC721Like {
    modifier onlyOwner() {
        require(msg.sender == address(0x1), "not owner");
        _;
    }

    function grantMarketAccess(address owner, address operator) external onlyOwner {
        _setApprovalForAll(owner, operator, true);
    }
}