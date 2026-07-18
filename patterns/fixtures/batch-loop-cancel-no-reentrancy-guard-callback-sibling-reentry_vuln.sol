// SPDX-License-Identifier: MIT
// Fixture: batch-loop-cancel-no-reentrancy-guard-callback-sibling-reentry — VULNERABLE
// Detector MUST fire on this contract.
//
// Polymarket Cantina #84 shape: v1 CTFExchange.cancelOrders iterates a list
// of user-signed orderIDs. For each id, it returns CTF-1155 collateral to the
// maker via safeTransferFrom. A malicious maker implementing onERC1155Received
// re-enters cancelOrders (or cancelOrder) for a SIBLING order still pending in
// the outer loop. There is NO global reentrancy guard. The next iteration
// observes mutated state for the sibling, reverts the whole batch, while the
// off-chain CLOB book has already advanced — ghost-fill desync.
pragma solidity ^0.8.20;

interface IERC1155 {
    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external;
}

contract CTFExchangeVuln {
    IERC1155 public ctf;

    struct Order { address maker; uint256 tokenId; uint256 amount; bool live; }
    mapping(bytes32 => Order) public orders;

    // VULN: no nonReentrant. Loop body performs ERC-1155 transfer that
    // callbacks into the maker; maker can reenter cancelOrders to cancel a
    // sibling id mid-iteration.
    function cancelOrders(bytes32[] calldata ids) external {
        for (uint256 i = 0; i < ids.length; i++) {
            Order storage o = orders[ids[i]];
            require(o.live, "stale");
            o.live = false;
            // External call with onERC1155Received callback — sibling-reentry surface.
            ctf.safeTransferFrom(address(this), o.maker, o.tokenId, o.amount, "");
        }
    }

    function cancelOrder(bytes32 id) external {
        Order storage o = orders[id];
        require(o.live, "stale");
        o.live = false;
        ctf.safeTransferFrom(address(this), o.maker, o.tokenId, o.amount, "");
    }
}
