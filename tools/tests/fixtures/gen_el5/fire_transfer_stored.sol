// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// STRONG: transfer to a STORED address (state var), 2300-stipend load-bearing.
contract FeeVault {
    address payable public treasury;   // stored payee
    uint256 accrued;

    function sweep() external {
        uint256 amt = accrued;
        accrued = 0;
        treasury.transfer(amt);        // <-- fires: transfer-stipend, medium
    }
}
