// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: vulnerable — _transferFrom uses netLpIn instead of netPtIn for PT transfer.
// Source: pendle-finance/pendle-core-v2-public@fa4b669

contract ExpiredLpPtRedeemer {
    address public PT;
    address public LP;

    function _transferFrom(address token, address from, address to, uint256 amount) internal {
        // transfers `amount` of `token` from `from` to `to`
    }

    // VULNERABLE: pulls netLpIn amount of PT instead of netPtIn
    function redeem(uint256 netLpIn, uint256 netPtIn) external returns (uint256 totalPtRedeem) {
        totalPtRedeem = 0;

        // Pull LP tokens (correct)
        if (netLpIn > 0) {
            _transferFrom(LP, msg.sender, address(this), netLpIn);
        }

        if (netPtIn > 0) {
            // BUG: uses netLpIn instead of netPtIn → pulls LP-priced amount of PT
            _transferFrom(PT, msg.sender, address(this), netLpIn);
            totalPtRedeem += netPtIn;
        }
    }
}
