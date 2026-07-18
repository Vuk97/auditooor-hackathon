// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SAFE (recommended form): call{value:x}("") to a stored address. Must be SILENT.
contract RobustPayout {
    address payable public treasury;
    uint256 accrued;

    function sweep() external {
        uint256 amt = accrued;
        accrued = 0;
        (bool ok, ) = treasury.call{value: amt}("");
        require(ok, "payout failed");
    }
}
