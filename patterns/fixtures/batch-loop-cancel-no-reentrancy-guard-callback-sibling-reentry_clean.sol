// SPDX-License-Identifier: MIT
// Fixture: batch-loop-cancel-no-reentrancy-guard-callback-sibling-reentry — CLEAN
// Detector MUST NOT fire on this contract.
//
// Fix: add nonReentrant modifier to cancelOrders (and cancelOrder), so a
// re-entrant call from onERC1155Received reverts before mutating any sibling
// state.
pragma solidity ^0.8.20;

interface IERC1155 {
    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external;
}

abstract contract ReentrancyGuard {
    uint256 private _status = 1;
    modifier nonReentrant() {
        require(_status != 2, "REENTRANCY_GUARD_LOCKED");
        _status = 2;
        _;
        _status = 1;
    }
}

contract CTFExchangeClean is ReentrancyGuard {
    IERC1155 public ctf;

    struct Order { address maker; uint256 tokenId; uint256 amount; bool live; }
    mapping(bytes32 => Order) public orders;

    function cancelOrders(bytes32[] calldata ids) external nonReentrant {
        for (uint256 i = 0; i < ids.length; i++) {
            Order storage o = orders[ids[i]];
            require(o.live, "stale");
            o.live = false;
            ctf.safeTransferFrom(address(this), o.maker, o.tokenId, o.amount, "");
        }
    }

    function cancelOrder(bytes32 id) external nonReentrant {
        Order storage o = orders[id];
        require(o.live, "stale");
        o.live = false;
        ctf.safeTransferFrom(address(this), o.maker, o.tokenId, o.amount, "");
    }
}
