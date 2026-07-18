// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
/// Same marketplace / auction settlement, but payouts use .call{value: amt}("")
/// with an explicit return-value check. No 2300-gas stipend, compatible with
/// Gnosis Safes and smart-contract wallets.
contract PayableTransferClean {
    mapping(address => uint256) public proceeds;

    function settle(address seller, uint256 amt) external {
        proceeds[seller] -= amt;
        (bool ok, ) = payable(seller).call{value: amt}("");
        require(ok, "send failed");
    }

    function refund(address buyer) external {
        uint256 amt = proceeds[buyer];
        proceeds[buyer] = 0;
        (bool ok, ) = payable(buyer).call{value: amt}("");
        require(ok, "refund failed");
    }
}
