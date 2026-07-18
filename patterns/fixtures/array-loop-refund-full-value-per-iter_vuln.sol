// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ArrayLoopRefundVuln {
    // VULN: loop refunds msg.value * rate / 100 per iteration with no
    // running-balance decrement. Attacker-supplied N recipients at 10%
    // refund each drains the contract. Detector fires because the body
    // has a for-loop + msg.value*rate transfer + no `remaining -=`.
    function buy(
        address[] calldata recipients,
        uint256[] calldata rates,
        bool[] calldata refundFlags
    ) external payable {
        for (uint256 i = 0; i < recipients.length; i++) {
            if (refundFlags[i]) {
                uint256 refund = msg.value * rates[i] / 100;
                (bool ok, ) = recipients[i].call{value: refund}("");
                require(ok, "refund failed");
            }
        }
    }

    receive() external payable {}
}
