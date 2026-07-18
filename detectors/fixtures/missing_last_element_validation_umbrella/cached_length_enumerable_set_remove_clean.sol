// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library EnumerableSetCachedLenClean {
    struct AddressSet {
        address[] _values;
        mapping(address => uint256) _indexes;
    }

    function add(AddressSet storage set, address value) internal returns (bool) {
        if (set._indexes[value] == 0) {
            set._values.push(value);
            set._indexes[value] = set._values.length;
            return true;
        }
        return false;
    }

    function remove(AddressSet storage set, address value) internal returns (bool) {
        uint256 valueIndex = set._indexes[value];
        if (valueIndex == 0) return false;

        uint256 toDeleteIndex = valueIndex - 1;
        uint256 lastIndex = set._values.length - 1;
        address lastValue = set._values[lastIndex];

        set._values[toDeleteIndex] = lastValue;
        set._indexes[lastValue] = toDeleteIndex + 1;

        set._values.pop();
        delete set._indexes[value];
        return true;
    }

    function length(AddressSet storage set) internal view returns (uint256) {
        return set._values.length;
    }

    function at(AddressSet storage set, uint256 index) internal view returns (address) {
        require(index < set._values.length, "EnumerableSet: index out of bounds");
        return set._values[index];
    }
}

contract CachedLengthEnumerableSetRemoveClean {
    using EnumerableSetCachedLenClean for EnumerableSetCachedLenClean.AddressSet;

    EnumerableSetCachedLenClean.AddressSet private blacklist;
    mapping(address => bool) public shouldRemove;

    function seed(address a, address b) external {
        blacklist.add(a);
        blacklist.add(b);
        shouldRemove[a] = true;
        shouldRemove[b] = true;
    }

    function sweep() external {
        address[] memory toRemove = new address[](blacklist.length());
        uint256 removeCount;

        for (uint256 i = 0; i < blacklist.length(); i++) {
            address account = blacklist.at(i);
            if (shouldRemove[account]) {
                toRemove[removeCount] = account;
                removeCount++;
            }
        }

        for (uint256 i = 0; i < removeCount; i++) {
            blacklist.remove(toRemove[i]);
        }
    }
}
