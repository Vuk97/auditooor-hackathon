// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EoaRestrictedModifiersThatChecksTheBytecodeSizeOfTheCallerAClean {
    uint256 public minted;

    modifier onlyEOA() {
        require(tx.origin == msg.sender, "only EOA");
        _;
    }

    function mint() external onlyEOA {
        minted += 1;
    }
}
