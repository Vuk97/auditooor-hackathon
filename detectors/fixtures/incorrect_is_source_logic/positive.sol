// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IncorrectIsSourceLogicPositive {
    function isSource(
        string memory denom,
        string memory sourcePort,
        string memory sourceChannel
    ) public pure returns (bool) {
        string memory prefix = string.concat(sourcePort, "/", sourceChannel, "/");
        return _startsWith(denom, prefix);
    }

    function _startsWith(string memory value, string memory prefix) internal pure returns (bool) {
        bytes memory valueBytes = bytes(value);
        bytes memory prefixBytes = bytes(prefix);
        if (prefixBytes.length > valueBytes.length) {
            return false;
        }
        for (uint256 i = 0; i < prefixBytes.length; i++) {
            if (valueBytes[i] != prefixBytes[i]) {
                return false;
            }
        }
        return true;
    }
}
