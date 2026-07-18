// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: the freeze flag can be flipped by any caller - no authority guard.
contract FreezeFlagFlipVulnerable {
    address public admin;
    bool public freezeFlag;

    function setFreezeFlag(bool v) external {
        freezeFlag = v;
    }
}
