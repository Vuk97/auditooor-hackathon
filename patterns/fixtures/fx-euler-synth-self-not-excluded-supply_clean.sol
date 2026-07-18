// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: fixed — constructor adds address(this) to ignoredForTotalSupply.
// Source: euler-xyz/euler-vault-kit@06cc3c0 (Cantina-68 fix)

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

contract ESynth {
    using EnumerableSet for EnumerableSet.AddressSet;

    EnumerableSet.AddressSet internal ignoredForTotalSupply;
    mapping(address => uint256) private _balances;
    uint256 private _totalMinted;

    address public owner;

    // FIXED: address(this) excluded so self-mints don't inflate totalSupply
    constructor(address owner_) {
        owner = owner_;
        ignoredForTotalSupply.add(address(this));
    }

    function totalSupply() public view returns (uint256) {
        uint256 ignored;
        address[] memory ignoredAddrs = ignoredForTotalSupply.values();
        for (uint256 i = 0; i < ignoredAddrs.length; i++) {
            ignored += _balances[ignoredAddrs[i]];
        }
        return _totalMinted - ignored;
    }

    function mint(address to, uint256 amount) external {
        _balances[to] += amount;
        _totalMinted += amount;
    }
}
