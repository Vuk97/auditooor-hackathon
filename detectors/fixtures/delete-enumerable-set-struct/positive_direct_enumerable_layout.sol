// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DirectEnumerableDeletePositive {
    struct Set {
        bytes32[] _values;
        mapping(bytes32 => uint256) _indexes;
    }

    mapping(bytes32 => Set) private sets;

    function clear(bytes32 id) external {
        delete sets[id];
    }
}
