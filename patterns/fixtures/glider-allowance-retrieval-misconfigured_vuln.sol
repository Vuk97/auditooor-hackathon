// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TokenVuln {
    // VULN: every spender has infinite allowance
    function allowance(address, address) external pure returns (uint256) {
        return type(uint256).max;
    }
}
