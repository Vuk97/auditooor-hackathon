// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: vulnerable — claimVerified return array never initialized, out-of-bounds write.
// Source: pendle-finance/pendle-core-v2-public@4df7abc

contract PendleMultiTokenMerkleDistributor {
    mapping(address => mapping(address => uint256)) private _claimedAmounts;

    // VULNERABLE: amountOuts is uninitialized zero-length array; amountOuts[i] = x reverts
    function claimVerified(
        address receiver,
        address[] memory tokens
    ) external returns (uint256[] memory amountOuts) {
        // amountOuts is default-initialized as length-0 array — NOT initialized here
        address user = msg.sender;
        uint256 nToken = tokens.length;

        for (uint256 i = 0; i < nToken; ++i) {
            address token = tokens[i];
            uint256 amount = _claimedAmounts[user][token];
            // BUG: amountOuts is zero-length → amountOuts[i] is out-of-bounds → PANIC
            amountOuts[i] = amount;
        }
    }
}
