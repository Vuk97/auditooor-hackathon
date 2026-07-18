// SPDX-License-Identifier: MIT
// Fixture: swap-reentrancy-via-aggregator — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

interface IAggregator {
    function swap(bytes calldata data) external payable returns (uint256);
}

// Minimal nonReentrant implementation (identical shape to OZ ReentrancyGuard).
abstract contract ReentrancyGuard {
    uint256 private _status = 1;

    modifier nonReentrant() {
        require(_status != 2, "REENTRANT");
        _status = 2;
        _;
        _status = 1;
    }
}

contract SwapAggregatorClean is ReentrancyGuard {
    uint256 public totalSwapped;

    // CLEAN fix: nonReentrant modifier applied on every payable aggregator wrapper.
    function swapAndBridge(address router, bytes calldata data)
        external
        payable
        nonReentrant
    {
        (bool ok, ) = router.call{value: msg.value}(data);
        require(ok, "swap failed");
        totalSwapped += msg.value;
    }

    function swapViaAggregator(address aggregator, bytes calldata payload)
        external
        payable
        nonReentrant
    {
        IAggregator(aggregator).swap{value: msg.value}(payload);
        totalSwapped += msg.value;
    }

    function swapTokens(address router, bytes calldata data)
        external
        payable
        nonReentrant
    {
        (bool ok, ) = router.call{value: msg.value}(data);
        require(ok, "swap failed");
    }
}
