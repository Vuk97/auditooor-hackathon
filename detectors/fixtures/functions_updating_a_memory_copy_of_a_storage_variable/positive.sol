// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FunctionsUpdatingAMemoryCopyOfAStorageVariablePositive {
    struct AccountConfig {
        uint256 weight;
        bool frozen;
    }

    AccountConfig internal accountConfig;

    function updateAccountConfig() external {
        AccountConfig memory snapshot = accountConfig;
        snapshot.weight += 1;
        snapshot.frozen = true;
    }
}
