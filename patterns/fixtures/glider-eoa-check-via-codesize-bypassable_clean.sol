// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EOACheckClean {
    mapping(address => bool) public minted;

    function mint() external {
        require(tx.origin == msg.sender, "only EOA");
        require(!minted[msg.sender], "already");
        minted[msg.sender] = true;
    }
}