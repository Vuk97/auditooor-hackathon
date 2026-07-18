// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultFallbackClean {
    uint256 public total;

    receive() external payable {
        total += msg.value;
    }

    fallback() external {
        revert("no calldata route");
    }
}
