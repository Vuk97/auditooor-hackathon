// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: same shape, but guarded by onlyOwner. Detector must NOT fire.
contract CleanToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
        totalSupply += amount;
    }
}
