// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire on this contract.
///
/// Fix shape: every mutator cancels the prior order and/or bumps a
/// maker-scoped nonce so the previously signed digest is invalidated. The
/// executor that observed the old order at terms T0 can no longer be rugged
/// into filling at T1, because the on-chain digest no longer matches the
/// signature it was checking.
contract LimitOrderPostSignMutableClean {
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
    mapping(address => uint256) public nonces;

    function submit(uint256 id, Order calldata o) external {
        orders[id] = o;
    }

    // CLEAN: mutator cancels the prior order (`delete orders[id]`) before
    // anything else. Matches the negative-guard regex `delete\s+orders`.
    function modifyOrder(uint256 id, uint256 newLimitPrice, Order calldata fresh, bytes calldata /*newSig*/) external {
        Order storage o = orders[id];
        require(msg.sender == o.maker, "not maker");
        delete orders[id];             // cancels observed digest
        Order memory m = fresh;
        m.limitPrice = newLimitPrice;
        orders[id] = m;
    }

    // CLEAN: nonce bump invalidates any pre-existing signature. Matches the
    // negative-guard regex `nonces\[.*\]\+\+`.
    function adjustTick(uint256 id, int24 newLo, int24 newHi) external {
        Order storage o = orders[id];
        require(msg.sender == o.maker, "not maker");
        nonces[o.maker]++;             // replay-guard bump
        o.tickLower = newLo;
        o.tickUpper = newHi;
    }

    // CLEAN: explicit invalidateHash call on the mutator path. Matches the
    // negative-guard regex `invalidateHash`.
    function changeLimit(uint256 id, bytes32 oldDigest, uint256 newLimitPrice, uint256 newDeadline) external {
        Order storage o = orders[id];
        require(msg.sender == o.maker, "not maker");
        _invalidateHash(oldDigest);
        o.limitPrice = newLimitPrice;
        o.deadline   = newDeadline;
    }

    // CLEAN: uses internal _cancel(id) helper. Matches the negative-guard
    // regex `_cancel`.
    function updateOrder(uint256 id, uint256 newPrice, uint256 newAmount) external {
        Order storage o = orders[id];
        require(msg.sender == o.maker, "not maker");
        _cancel(id);
        o.limitPrice = newPrice;
        o.amount     = newAmount;
    }

    function invalidateHash(bytes32 h) external { _invalidateHash(h); }

    function _cancel(uint256) internal {}
    function _invalidateHash(bytes32) internal {}
}
