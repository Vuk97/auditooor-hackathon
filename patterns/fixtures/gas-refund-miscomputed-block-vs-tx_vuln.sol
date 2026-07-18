// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// gas-refund-miscomputed-block-vs-tx detector. DO NOT DEPLOY.
///
/// The relayer reimburses the submitter based on `block.gaslimit` rather
/// than the gas actually consumed by this transaction. Because a single tx
/// almost never approaches the block-wide gas limit, every relayed call
/// drains the float for the whole block budget.
contract GasRefundVuln {
    mapping(address => uint256) public deposits;

    function relay(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "relay failed");

        // BUG: block.gaslimit is a block header value, not per-tx spend.
        // The refund is wildly inflated vs gas actually burned.
        uint256 gasRefund = block.gaslimit * tx.gasprice;
        (bool paid, ) = msg.sender.call{value: gasRefund}("");
        require(paid, "_refund fail");
    }
}
