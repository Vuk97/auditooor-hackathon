// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OrderTreeClean {
    struct Node { uint256 prev; uint256 next; uint256 amount; }
    mapping(uint256 => Node) public orders;
    uint256 public head;
    uint256 public tail;
    uint256 public size;

    // CLEAN: single exit with unconditional size--
    function _remove(uint256 id) internal {
        Node storage n = orders[id];
        if (id == tail) {
            tail = n.prev;
            orders[n.prev].next = 0;
        } else {
            orders[n.prev].next = n.next;
            orders[n.next].prev = n.prev;
        }
        delete orders[id];
        size--;
    }

    function cancel(uint256 id) external {
        _remove(id);
    }
}
