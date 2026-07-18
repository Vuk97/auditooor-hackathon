// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// Minimal inlined OpenZeppelin-shaped EnumerableSet.AddressSet (swap-and-pop on
/// remove). Self-contained so the fixture compiles with bare solc (no remappings).
library EnumerableSet {
    struct AddressSet {
        address[] _values;
        mapping(address => uint256) _indexes; // 1-based
    }

    function add(AddressSet storage set, address value) internal returns (bool) {
        if (set._indexes[value] != 0) return false;
        set._values.push(value);
        set._indexes[value] = set._values.length;
        return true;
    }

    function remove(AddressSet storage set, address value) internal returns (bool) {
        uint256 idx = set._indexes[value];
        if (idx == 0) return false;
        uint256 toDelete = idx - 1;
        uint256 lastIndex = set._values.length - 1;
        if (toDelete != lastIndex) {
            address last = set._values[lastIndex];
            set._values[toDelete] = last;     // swap LAST element into removed slot
            set._indexes[last] = idx;
        }
        set._values.pop();
        delete set._indexes[value];
        return true;
    }

    function at(AddressSet storage set, uint256 index) internal view returns (address) {
        return set._values[index];
    }

    function length(AddressSet storage set) internal view returns (uint256) {
        return set._values.length;
    }
}

/// FORWARD loop reads `members.at(i)` and `members.remove(...)` in the SAME body
/// while `i` increments monotonically. EnumerableSet.remove swaps the LAST element
/// into slot `i`, so the swapped-in element is SKIPPED (iteration-skip). FLAGGED.
contract EnumsetRemoveInLoopSuspect {
    using EnumerableSet for EnumerableSet.AddressSet;

    EnumerableSet.AddressSet private members;

    function purgeAll() external {
        for (uint256 i = 0; i < members.length(); i++) {
            address m = members.at(i);
            members.remove(m);
        }
    }
}
