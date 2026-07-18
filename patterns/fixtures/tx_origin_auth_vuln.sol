// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TxOriginVuln {
    address public owner;

    constructor() { owner = msg.sender; }

    // VULN: tx.origin used for auth → phishable
    function setOwner(address newOwner) external {
        require(tx.origin == owner, "not owner");
        owner = newOwner;
    }

    function privileged(uint256 x) external view returns (uint256) {
        require(tx.origin == owner, "no");
        return x * 2;
    }
}
