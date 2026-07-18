// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library SimpleEnumerableSet {
    struct AddressSet {
        address[] _values;
    }

    function length(AddressSet storage set) internal view returns (uint256) {
        return set._values.length;
    }

    function at(AddressSet storage set, uint256 index) internal view returns (address) {
        return set._values[index];
    }

    function add(AddressSet storage set, address value) internal returns (bool) {
        for (uint256 i = 0; i < set._values.length; i++) {
            if (set._values[i] == value) {
                return false;
            }
        }
        set._values.push(value);
        return true;
    }

    function remove(AddressSet storage set, address value) internal returns (bool) {
        for (uint256 i = 0; i < set._values.length; i++) {
            if (set._values[i] == value) {
                set._values[i] = set._values[set._values.length - 1];
                set._values.pop();
                return true;
            }
        }
        return false;
    }
}

// CLEAN: reverse iteration keeps the swapped-in tail on the current index.
contract CachedSwapPopSetForwardRemoveClean {
    using SimpleEnumerableSet for SimpleEnumerableSet.AddressSet;

    SimpleEnumerableSet.AddressSet private members;

    function seed(address first, address second) external {
        members.add(first);
        members.add(second);
    }

    function sweepMembers() external {
        for (uint256 i = members.length(); i > 0; i--) {
            address current = members.at(i - 1);
            members.remove(current);
        }
    }
}
