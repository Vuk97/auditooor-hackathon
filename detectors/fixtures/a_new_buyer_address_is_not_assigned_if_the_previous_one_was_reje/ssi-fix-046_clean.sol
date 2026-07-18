// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ANewBuyerAddressIsNotAssignedIfThePreviousOneWasRejeClean {
    address public buyer;
    uint256 public deposited;

    constructor() {
        buyer = address(0xBEEF);
        deposited = 1 ether;
    }

    function rejectBuyerAndReopenEscrow() external {
        require(buyer != address(0), "buyer missing");
        require(deposited > 0, "deposit missing");
        _refreshEscrowState();
    }

    function _refreshEscrowState() internal {
        buyer = address(0);
        deposited = 0;
    }
}
