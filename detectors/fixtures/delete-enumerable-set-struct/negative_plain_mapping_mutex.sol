// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PlainMappingMutexNegative {
    mapping(bytes32 => address) private _filled;

    function fill(bytes32 commitment) external {
        _filled[commitment] = msg.sender;
        delete _filled[commitment];
    }
}
