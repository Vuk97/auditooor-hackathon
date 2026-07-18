// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RecipientsVuln {
    address[] public recipients;
    mapping(address => uint256) public amount;
    address public owner;

    constructor() { owner = msg.sender; }

    // Detector MUST fire: push without duplicate check.
    function addRecipient(address r, uint256 a) external {
        require(msg.sender == owner, "only owner");
        recipients.push(r);
        amount[r] = a;
    }
}
