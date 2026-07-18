// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library EnumerableUintSetVuln {
    struct UintSet {
        uint256[] _values;
        mapping(uint256 => uint256) _indexes;
    }

    function add(UintSet storage set, uint256 value) internal returns (bool) {
        if (set._indexes[value] == 0) {
            set._values.push(value);
            set._indexes[value] = set._values.length;
            return true;
        }
        return false;
    }

    function remove(UintSet storage set, uint256 value) internal returns (bool) {
        uint256 valueIndex = set._indexes[value];
        if (valueIndex == 0) return false;

        uint256 toDeleteIndex = valueIndex - 1;
        uint256 lastIndex = set._values.length - 1;
        uint256 lastValue = set._values[lastIndex];

        set._values[toDeleteIndex] = lastValue;
        set._indexes[lastValue] = toDeleteIndex + 1;

        set._values.pop();
        delete set._indexes[value];
        return true;
    }

    function length(UintSet storage set) internal view returns (uint256) {
        return set._values.length;
    }

    function at(UintSet storage set, uint256 index) internal view returns (uint256) {
        require(index < set._values.length, "EnumerableSet: index out of bounds");
        return set._values[index];
    }
}

contract NestedAtRemoveUintSetVuln {
    using EnumerableUintSetVuln for EnumerableUintSetVuln.UintSet;

    EnumerableUintSetVuln.UintSet private pendingIds;
    mapping(uint256 => bool) public shouldPrune;

    function seed(uint256 a, uint256 b, uint256 c) external {
        pendingIds.add(a);
        pendingIds.add(b);
        pendingIds.add(c);
        shouldPrune[a] = true;
        shouldPrune[c] = true;
    }

    function prune() external {
        for (uint256 i = 0; i < pendingIds.length(); i++) {
            if (shouldPrune[pendingIds.at(i)]) {
                pendingIds.remove(pendingIds.at(i));
            }
        }
    }
}
