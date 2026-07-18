// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// limit-order-price-frontrun detector. DO NOT DEPLOY.
///
/// The Order struct is stored in mutable storage (orders[id]) and can be
/// rotated by the maker AFTER the off-chain signature was produced.
/// fillOrder reads order.limitPrice / order.makerAmount directly without
/// verifying any content hash of the mutable fields — the maker can
/// front-run a pending fill and rug the executor.
contract LimitOrderVuln {
    struct Order {
        address maker;
        uint256 limitPrice;
        uint256 makerAmount;
        uint256 takerAmount;
        uint256 duration;
        bytes sig;
    }

    mapping(uint256 => Order) public orders;

    function submit(uint256 id, Order calldata o) external {
        orders[id] = o;
    }

    // Maker can rotate price/size between signing and fill — no hash check.
    function updateOrder(uint256 id, uint256 newLimitPrice, uint256 newDuration) external {
        Order storage o = orders[id];
        require(msg.sender == o.maker, "not maker");
        o.limitPrice = newLimitPrice;
        o.duration = newDuration;
    }

    // VULNERABLE fill: reads order.limitPrice / order.makerAmount with no
    // keccak256 / hashOrder / orderHash / orderDigest / typedDataHash binding.
    function fillOrder(uint256 id) external {
        Order storage order = orders[id];
        uint256 proceeds = order.makerAmount * order.limitPrice;
        // ... execute fill using mutable fields ...
        order.makerAmount = 0;
        // no digest verification → maker can front-run updateOrder
        _settle(order.maker, msg.sender, proceeds);
    }

    function _settle(address, address, uint256) internal pure {}
}
