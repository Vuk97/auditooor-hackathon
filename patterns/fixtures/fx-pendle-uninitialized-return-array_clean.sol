// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: fixed — amountOuts initialized with new uint256[](nToken).
// Source: pendle-finance/pendle-core-v2-public@4df7abc

contract PendleMultiTokenMerkleDistributor {
    mapping(address => mapping(address => uint256)) private _claimedAmounts;

    // FIXED: amountOuts initialized to correct length before loop writes
    function claimVerified(
        address receiver,
        address[] memory tokens
    ) external returns (uint256[] memory amountOuts) {
        address user = msg.sender;
        uint256 nToken = tokens.length;
        amountOuts = new uint256[](nToken); // explicit initialization required

        for (uint256 i = 0; i < nToken; ++i) {
            address token = tokens[i];
            uint256 amount = _claimedAmounts[user][token];
            amountOuts[i] = amount;
        }
    }
}
