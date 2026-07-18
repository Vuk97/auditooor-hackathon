// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NestedEnumerableDeletePositive {
    struct Inner {
        bytes32[] _values;
        mapping(bytes32 => uint256) _indexes;
    }

    struct AddressSet {
        Inner _inner;
    }

    mapping(bytes32 => AddressSet) private addressSets;

    function clear(bytes32 id) external {
        delete addressSets[id];
    }
}
