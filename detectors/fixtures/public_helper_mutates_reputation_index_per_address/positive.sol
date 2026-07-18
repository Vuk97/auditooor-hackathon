// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReputationIndexOpenHelper {
    mapping(address => uint256[]) private _credIdsPerAddress;
    mapping(address => mapping(uint256 => uint256)) private _credIdIndexPerAddress;

    function _addCredIdPerAddress(uint256 credId, address sender_) public {
        if (_credIdIndexPerAddress[sender_][credId] != 0) {
            return;
        }

        _credIdsPerAddress[sender_].push(credId);
        _credIdIndexPerAddress[sender_][credId] = _credIdsPerAddress[sender_].length;
    }
}
