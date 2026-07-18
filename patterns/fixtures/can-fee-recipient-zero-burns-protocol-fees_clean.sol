// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FeeAdminClean {
    address public feeRecipient;
    address public owner;

    constructor(address initialRecipient) {
        require(initialRecipient != address(0), "zero recipient");
        owner = msg.sender;
        feeRecipient = initialRecipient;
    }

    // Clean: explicit zero-address guard.
    function setFeeRecipient(address newRecipient) external {
        require(msg.sender == owner, "only owner");
        require(newRecipient != address(0), "zero recipient");
        feeRecipient = newRecipient;
    }

    function doSomething(uint256 fee) external payable {
        if (feeRecipient != address(0) && fee > 0) {
            payable(feeRecipient).transfer(fee);
        }
    }
}
