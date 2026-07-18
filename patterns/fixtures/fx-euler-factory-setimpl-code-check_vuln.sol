// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: vulnerable — setImplementation only checks address(0), not code.length.
// Source: euler-xyz/euler-vault-kit@b5fc6f2 (Cantina-320 fix)
// Vulnerability: an EOA or self-destructed contract address passes the zero check.
// All beacon proxies immediately delegate to the new address, permanently bricking them
// because delegatecall to an EOA returns empty data and reverts on any meaningful call.

contract GenericFactory {
    address public implementation;

    error E_BadAddress();

    // VULNERABLE: only rejects address(0), not EOA/empty addresses
    function setImplementation(address newImplementation) external {
        if (newImplementation == address(0)) revert E_BadAddress();
        implementation = newImplementation;
    }
}
