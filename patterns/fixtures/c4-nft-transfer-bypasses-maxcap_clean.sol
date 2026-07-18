// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CappedNFTClean {
    uint256 public constant MAX_PER_USER = 3;
    mapping(address => uint256) public mintedPerUser;
    mapping(address => uint256) public heldPerUser;
    mapping(uint256 => address) public ownerOf;

    function mint(address to, uint256 id) external {
        require(heldPerUser[to] < MAX_PER_USER, "cap");
        heldPerUser[to]++;
        mintedPerUser[to]++;
        ownerOf[id] = to;
    }

    function transferFrom(address from, address to, uint256 id) external {
        require(ownerOf[id] == from, "owner");
        require(heldPerUser[to] < MAX_PER_USER, "maxCapPerUser");
        heldPerUser[from]--;
        heldPerUser[to]++;
        ownerOf[id] = to;
    }
}
