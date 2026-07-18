// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Math {
    function unsafeAdd(uint256 a, uint256 b) internal pure returns (uint256 c) {
        assembly {
            c := add(a, b)
        }
    }
}
