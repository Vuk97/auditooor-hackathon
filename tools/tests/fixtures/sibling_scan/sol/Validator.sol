// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library Validator {
    function validateAmount(uint256 amount) internal pure returns (bool) {
        return amount > 0 && amount <= 1e18;
    }
}
