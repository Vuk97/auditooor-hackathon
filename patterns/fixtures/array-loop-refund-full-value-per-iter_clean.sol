// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ArrayLoopRefundClean {
    // CLEAN: tracks a running `remaining` counter so the cumulative refund
    // is bounded by msg.value. Detector does NOT fire because the body
    // contains `remaining -=`.
    function buy(
        address[] calldata recipients,
        uint256[] calldata rates,
        bool[] calldata refundFlags
    ) external payable {
        uint256 remaining = msg.value;
        for (uint256 i = 0; i < recipients.length; i++) {
            if (refundFlags[i]) {
                uint256 refund = msg.value * rates[i] / 100;
                require(refund <= remaining, "insufficient for refund");
                remaining -= refund;
                (bool ok, ) = recipients[i].call{value: refund}("");
                require(ok, "refund failed");
            }
        }
    }

    receive() external payable {}
}
