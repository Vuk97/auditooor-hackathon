// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// limit-order-post-sign-modification-attack detector. DO NOT DEPLOY.
///
/// Bug shape (Solodit cluster C0072, 161 findings):
///   - Signed limit order is stored on-chain in mutable storage (orders[id]).
///   - Public modifyOrder / updateOrder / adjustTick / changeLimit rewrites
///     limitPrice, tickRange or deadline WITHOUT cancelling the prior order
///     or bumping any nonce / invalidating any digest.
///   - Executor who saw the order off-chain at terms T0 is front-run by the
///     maker calling a mutator, and fillOrder lands at adversarial terms T1.
contract LimitOrderPostSignMutableVuln {
    struct Order {
        address maker;
        uint256 limitPrice;
        int24   tickLower;
        int24   tickUpper;
        uint256 amount;
        uint256 deadline;
        bytes   sig;
    }

    mapping(uint256 => Order) public orders;

    function submit(uint256 id, Order calldata o) external {
        orders[id] = o;
    }

    // VULN #1: modifyOrder rewrites limitPrice in-place. No _cancel, no
    // delete orders[id], no nonce bump, no invalidateHash.
    function modifyOrder(uint256 id, uint256 newLimitPrice) external {
        Order storage o = orders[id];
        require(msg.sender == o.maker, "not maker");
        o.limitPrice = newLimitPrice; // writes `limitPrice` storage
    }

    // VULN #2: adjustTick rotates the tick range. An ITM executor can be
    // rugged by the maker moving the tick out of range mid-flight.
    function adjustTick(uint256 id, int24 newLo, int24 newHi) external {
        Order storage o = orders[id];
        require(msg.sender == o.maker, "not maker");
        o.tickLower = newLo;
        o.tickUpper = newHi;
    }

    // VULN #3: changeLimit combined price + deadline rotation. No digest
    // invalidation, so the previously observed signature remains fillable
    // against the mutated terms.
    function changeLimit(uint256 id, uint256 newLimitPrice, uint256 newDeadline) external {
        Order storage o = orders[id];
        require(msg.sender == o.maker, "not maker");
        o.limitPrice = newLimitPrice;
        o.deadline   = newDeadline;
    }

    // VULN #4: updateOrder bulk rewrite. Again no cancel / nonce bump.
    function updateOrder(uint256 id, uint256 newPrice, uint256 newAmount) external {
        Order storage o = orders[id];
        require(msg.sender == o.maker, "not maker");
        o.limitPrice = newPrice;
        o.amount     = newAmount;
    }
}
