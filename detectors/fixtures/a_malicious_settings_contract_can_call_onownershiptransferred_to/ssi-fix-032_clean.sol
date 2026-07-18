// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MaliciousSettingsOnOwnershipTransferredClean {
    mapping(address => bool) internal listedPairs;
    bool internal onOwnershipTransferredHookEnabled;

    function addPair(address pair) external {
        listedPairs[pair] = true;
        onOwnershipTransferredHookEnabled = true;
    }

    function removePair(address pair) external {
        delete listedPairs[pair];
        onOwnershipTransferredHookEnabled = false;
    }
}
