// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library EnumerableBytes32SetClean {
    struct Bytes32Set {
        bytes32[] _values;
        mapping(bytes32 => uint256) _indexes;
    }

    function add(Bytes32Set storage set, bytes32 value) internal returns (bool) {
        if (set._indexes[value] == 0) {
            set._values.push(value);
            set._indexes[value] = set._values.length;
            return true;
        }
        return false;
    }

    function remove(Bytes32Set storage set, bytes32 value) internal returns (bool) {
        uint256 valueIndex = set._indexes[value];
        if (valueIndex == 0) return false;

        uint256 toDeleteIndex = valueIndex - 1;
        uint256 lastIndex = set._values.length - 1;
        bytes32 lastValue = set._values[lastIndex];

        set._values[toDeleteIndex] = lastValue;
        set._indexes[lastValue] = toDeleteIndex + 1;

        set._values.pop();
        delete set._indexes[value];
        return true;
    }

    function length(Bytes32Set storage set) internal view returns (uint256) {
        return set._values.length;
    }

    function at(Bytes32Set storage set, uint256 index) internal view returns (bytes32) {
        require(index < set._values.length, "EnumerableSet: index out of bounds");
        return set._values[index];
    }
}

contract Bytes32CachedLengthRemoveClean {
    using EnumerableBytes32SetClean for EnumerableBytes32SetClean.Bytes32Set;

    EnumerableBytes32SetClean.Bytes32Set private tags;
    mapping(bytes32 => bool) public shouldRemove;

    function seed(bytes32 a, bytes32 b, bytes32 c) external {
        tags.add(a);
        tags.add(b);
        tags.add(c);
        shouldRemove[a] = true;
        shouldRemove[c] = true;
    }

    function prune() external {
        uint256 liveLength = tags.length();
        bytes32[] memory toRemove = new bytes32[](liveLength);
        uint256 removeCount;

        for (uint256 i = 0; i < liveLength; i++) {
            bytes32 tag = tags.at(i);
            if (shouldRemove[tag]) {
                toRemove[removeCount] = tag;
                removeCount++;
            }
        }

        for (uint256 i = 0; i < removeCount; i++) {
            tags.remove(toRemove[i]);
        }
    }
}
