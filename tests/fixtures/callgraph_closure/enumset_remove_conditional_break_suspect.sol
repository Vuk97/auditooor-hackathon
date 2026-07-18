// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// Minimal inlined EnumerableSet (swap-and-pop on remove). Self-contained.
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

/// FORWARD loop reads `members.at(i)` and `members.remove(...)` on the SAME
/// collection. After the UNCONDITIONAL remove on every iteration, a `break` fires
/// ONLY on a conditional branch (`if (stop)`); on the NON-breaking path control
/// flows to the loop back-edge (`i++` then re-test) AFTER the swap-and-pop. The
/// post-remove path to the back-edge that does NOT pass through break/return still
/// exists, so the iteration-skip hazard is REAL. FLAGGED.
contract EnumsetRemoveConditionalBreakSuspect {
    using EnumerableSet for EnumerableSet.AddressSet;

    EnumerableSet.AddressSet private members;

    function purgeMaybe(bool stop) external {
        for (uint256 i = 0; i < members.length(); i++) {
            address m = members.at(i);
            members.remove(m);
            if (stop) {
                break;
            }
        }
    }
}
