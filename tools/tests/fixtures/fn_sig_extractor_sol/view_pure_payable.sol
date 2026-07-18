// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MutabilityVariants {
    uint256 private _stored;

    function getStored() external view returns (uint256) {
        return _stored;
    }

    function hashData(bytes calldata data) external pure returns (bytes32) {
        return keccak256(data);
    }

    function deposit() external payable returns (uint256) {
        return msg.value;
    }

    function privateHelper(uint256 x) private returns (uint256) {
        _stored = x;
        return x;
    }

    function multiReturn() external view returns (uint256 a, bool b, address c) {
        return (_stored, true, address(0));
    }
}
