// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// Minimal inlined EnumerableSet. Self-contained.
library EnumerableSet {
    struct AddressSet {
        address[] _values;
        mapping(address => uint256) _indexes;
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
            set._values[toDelete] = last;
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

/// FORWARD loop over a FIXED-SIZE memory array `targets`, removing each from the
/// set. The loop counter `i` indexes `targets` (a local memory array), NOT the set
/// via `set.at(i)`. The set is only `remove()`d by a fixed key, so the swap-and-pop
/// does not interact with the advancing counter. NEVER flagged (no at(i)-by-counter
/// on the removed collection -> never-FP).
contract EnumsetRemoveFixedKeyClean {
    using EnumerableSet for EnumerableSet.AddressSet;

    EnumerableSet.AddressSet private members;

    function purgeList(address[] calldata targets) external {
        for (uint256 i = 0; i < targets.length; i++) {
            members.remove(targets[i]);
        }
    }
}
