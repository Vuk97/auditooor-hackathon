// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: only the admin may flip the freeze flag.
contract FreezeFlagFlipSafe {
    address public admin;
    bool public freezeFlag;

    function setFreezeFlag(bool v) external {
        require(msg.sender == admin, "not admin");
        freezeFlag = v;
    }
}
