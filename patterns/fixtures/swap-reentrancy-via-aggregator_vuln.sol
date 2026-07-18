// SPDX-License-Identifier: MIT
// Fixture: swap-reentrancy-via-aggregator — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

interface IAggregator {
    function swap(bytes calldata data) external payable returns (uint256);
}

// VULN: payable aggregator wrapper forwards msg.value to a user-supplied
// router with no nonReentrant guard. A malicious router can reenter
// swapAndBridge/swapViaAggregator and replay the swap against one deposit.
contract SwapAggregatorVuln {
    uint256 public totalSwapped;

    // Matches name regex `^swapAndBridge$`, payable, has_external_call, no guard.
    function swapAndBridge(address router, bytes calldata data) external payable {
        (bool ok, ) = router.call{value: msg.value}(data);
        require(ok, "swap failed");
        totalSwapped += msg.value;
    }

    // Matches name regex `^swapViaAggregator$`, payable, has_external_call, no guard.
    function swapViaAggregator(address aggregator, bytes calldata payload) external payable {
        IAggregator(aggregator).swap{value: msg.value}(payload);
        totalSwapped += msg.value;
    }

    // Matches name regex `^swapTokens$`, payable, has_external_call, no guard.
    function swapTokens(address router, bytes calldata data) external payable {
        (bool ok, ) = router.call{value: msg.value}(data);
        require(ok, "swap failed");
    }
}
