// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OrderTreeVuln {
    struct Node { uint256 prev; uint256 next; uint256 amount; }
    mapping(uint256 => Node) public orders;
    uint256 public head;
    uint256 public tail;
    uint256 public size;

    function _remove(uint256 id) internal {
        Node storage n = orders[id];
        if (id == tail) {
            // VULN: tail branch rewires but doesn't decrement size
            tail = n.prev;
            orders[n.prev].next = 0;
            delete orders[id];
            return;
        }
        orders[n.prev].next = n.next;
        orders[n.next].prev = n.prev;
        delete orders[id];
        size--;
    }

    function cancel(uint256 id) external {
        _remove(id);
    }
}
