// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library EnumerableSet {
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

    function contains(AddressSet storage set, address value) internal view returns (bool) {
        return set._indexes[value] != 0;
    }

    function length(AddressSet storage set) internal view returns (uint256) {
        return set._values.length;
    }

    function at(AddressSet storage set, uint256 index) internal view returns (address) {
        require(index < set._values.length, "EnumerableSet: index out of bounds");
        return set._values[index];
    }
}

contract EnumerableSetSkipClean {
    using EnumerableSet for EnumerableSet.AddressSet;

    EnumerableSet.AddressSet private _blacklist;
    mapping(address => uint256) public expiresAt;

    function addToBlacklist(address account, uint256 expiration) external {
        _blacklist.add(account);
        expiresAt[account] = expiration;
    }

    function sweepExpired() external {
        for (uint256 i = _blacklist.length(); i > 0; i--) {
            address account = _blacklist.at(i - 1);
            if (expiresAt[account] < block.timestamp) {
                _blacklist.remove(account);
            }
        }
    }
}