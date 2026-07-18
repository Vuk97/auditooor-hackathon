// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RecipientsClean {
    address[] public recipients;
    mapping(address => bool) public added;
    mapping(address => uint256) public amount;
    address public owner;

    constructor() { owner = msg.sender; }

    // Detector MUST NOT fire: duplicate check via `added` mapping before push.
    function addRecipient(address r, uint256 a) external {
        require(msg.sender == owner, "only owner");
        require(!added[r], "duplicate");
        added[r] = true;
        recipients.push(r);
        amount[r] = a;
    }
}
