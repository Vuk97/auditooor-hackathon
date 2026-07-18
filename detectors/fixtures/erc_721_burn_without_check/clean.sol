// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BurnableCollectibleClean {
    mapping(uint256 => address) public ownerOf;

    function mint(address to, uint256 tokenId) external {
        ownerOf[tokenId] = to;
    }

    function burn(uint256 tokenId) external {
        require(ownerOf[tokenId] == msg.sender, "not owner");
        _burn(tokenId);
    }

    function _burn(uint256 tokenId) internal {
        delete ownerOf[tokenId];
    }
}
