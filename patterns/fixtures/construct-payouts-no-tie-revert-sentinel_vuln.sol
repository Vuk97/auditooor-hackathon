// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: UmaCtfAdapter-shaped payouts producer. `_constructPayouts(price)`
// emits the payout vector verbatim from the DVM oracle output. The
// `0.5 ether` UMA "tie / unknown" sentinel maps to `[1, 1]`, which is a
// valid 50/50 distribution against vanilla ConditionalTokens but is
// rejected by the downstream NegRiskOperator consumer that enforces
// `sum(payouts) == 1`. Resolution call reverts forever — market bricked.
contract UmaCtfAdapterVuln {
    error InvalidOOPrice();

    function _constructPayouts(int256 price) external pure returns (uint256[] memory) {
        uint256[] memory payouts = new uint256[](2);
        if (price != 0 && price != 0.5 ether && price != 1 ether) revert InvalidOOPrice();

        if (price == 0) {
            payouts[0] = 0;
            payouts[1] = 1;
        } else if (price == 0.5 ether) {
            // UNKNOWN: Report [Yes, No] as [1, 1], 50/50.
            // NO defensive check that the consumer accepts a tied vector.
            payouts[0] = 1;
            payouts[1] = 1;
        } else {
            payouts[0] = 1;
            payouts[1] = 0;
        }
        return payouts;
    }
}
