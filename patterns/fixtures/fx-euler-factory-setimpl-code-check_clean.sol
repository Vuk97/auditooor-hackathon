// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: fixed — setImplementation checks code.length instead of address(0).
// Source: euler-xyz/euler-vault-kit@b5fc6f2 (Cantina-320 fix)

contract GenericFactory {
    address public implementation;

    error E_BadAddress();

    // FIXED: code.length > 0 rejects EOAs, address(0), and self-destructed contracts
    function setImplementation(address newImplementation) external {
        if (newImplementation.code.length == 0) revert E_BadAddress();
        implementation = newImplementation;
    }
}
