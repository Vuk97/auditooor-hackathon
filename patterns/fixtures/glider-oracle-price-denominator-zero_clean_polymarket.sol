// SPDX-License-Identifier: MIT
// Phase 40 negative fixture — mirrors Polymarket CalculatorHelper.sol.
// `price` here is computed locally from EIP-712 maker-signed order amounts,
// NOT an oracle reading. The detector must NOT fire on this file because
// the function body contains no oracle ABI token (no latestAnswer / getPrice
// / Chainlink / Pyth / Uniswap-TWAP reference) and the contract has no
// oracle interface either.
pragma solidity ^0.8.20;

library CalcHelperClean {
    uint256 internal constant ONE = 10 ** 18;

    function calcPrice(uint256 makerAmount, uint256 takerAmount)
        internal
        pure
        returns (uint256)
    {
        // Pure arithmetic on user-signed order data — no oracle anywhere.
        return makerAmount * ONE / takerAmount;
    }

    function calculateFee(
        uint256 feeRateBps,
        uint256 outcomeTokens,
        uint256 makerAmount,
        uint256 takerAmount
    ) internal pure returns (uint256 fee) {
        uint256 price = calcPrice(makerAmount, takerAmount);
        if (price > 0 && price <= ONE) {
            fee = (feeRateBps * outcomeTokens) / (price * 10_000);
        }
    }
}
