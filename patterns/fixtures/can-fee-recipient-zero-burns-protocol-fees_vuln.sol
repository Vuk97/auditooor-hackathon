// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FeeAdminVuln {
    address public feeRecipient;
    address public owner;

    constructor() { owner = msg.sender; }

    // BUG: no zero-address check.
    function setFeeRecipient(address newRecipient) external {
        require(msg.sender == owner, "only owner");
        feeRecipient = newRecipient;
    }

    // The protected action — if feeRecipient == 0 then transfer reverts on OZ ERC20.
    function doSomething(uint256 fee) external payable {
        payable(feeRecipient).transfer(fee);
    }
}
