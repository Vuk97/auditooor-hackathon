// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CappedNFTVuln {
    uint256 public constant MAX_PER_USER = 3;
    mapping(address => uint256) public mintedPerUser;
    mapping(uint256 => address) public ownerOf;

    function mint(address to, uint256 id) external {
        require(mintedPerUser[to] < MAX_PER_USER, "cap");
        mintedPerUser[to]++;
        ownerOf[id] = to;
    }

    /// VULN: transferFrom does not re-check cap for `to`.
    function transferFrom(address from, address to, uint256 id) external {
        require(ownerOf[id] == from, "owner");
        ownerOf[id] = to;
    }
}
