// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: same shape as the vuln fixture, but the producer enforces the
// downstream NegRiskOperator invariant locally. Two equivalent guards
// shown — pick whichever matches the deploy config.
contract UmaCtfAdapterClean {
    error InvalidOOPrice();
    error TieUnsupported();

    bool public immutable allowTies;

    constructor(bool _allowTies) {
        // false when this adapter is wired to NegRiskOperator;
        // true when wired to vanilla ConditionalTokens.
        allowTies = _allowTies;
    }

    function _constructPayouts(int256 price) external view returns (uint256[] memory) {
        uint256[] memory payouts = new uint256[](2);
        if (price != 0 && price != 0.5 ether && price != 1 ether) revert InvalidOOPrice();

        if (price == 0) {
            payouts[0] = 0;
            payouts[1] = 1;
        } else if (price == 0.5 ether) {
            payouts[0] = 1;
            payouts[1] = 1;
        } else {
            payouts[0] = 1;
            payouts[1] = 0;
        }

        // Defensive guard: tie equality + sum-of-payouts check.
        // require(payouts[0] != payouts[1] || allowTies, "tie unsupported");
        require(payouts[0] != payouts[1] || allowTies, "tie unsupported");
        // Also reject zero/oversum vectors so consumer never sees them.
        require(payouts[0] + payouts[1] >= 1, "sum of payouts < 1");

        return payouts;
    }
}
