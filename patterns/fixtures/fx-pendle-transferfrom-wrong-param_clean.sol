// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: fixed — _transferFrom uses correct netPtIn parameter.
// Source: pendle-finance/pendle-core-v2-public@fa4b669

contract ExpiredLpPtRedeemer {
    address public PT;
    address public LP;

    function _transferFrom(address token, address from, address to, uint256 amount) internal {
        // transfers `amount` of `token` from `from` to `to`
    }

    // FIXED: netPtIn used for PT transfer
    function redeem(uint256 netLpIn, uint256 netPtIn) external returns (uint256 totalPtRedeem) {
        totalPtRedeem = 0;

        if (netLpIn > 0) {
            _transferFrom(LP, msg.sender, address(this), netLpIn);
        }

        if (netPtIn > 0) {
            _transferFrom(PT, msg.sender, address(this), netPtIn); // correct parameter
            totalPtRedeem += netPtIn;
        }
    }
}
