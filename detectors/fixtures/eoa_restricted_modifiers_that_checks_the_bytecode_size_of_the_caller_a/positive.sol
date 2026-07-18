// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EoaRestrictedModifiersThatChecksTheBytecodeSizeOfTheCallerAPositive {
    uint256 public minted;

    modifier onlyEOA() {
        require(msg.sender.code.length == 0, "only EOA");
        _;
    }

    function mint() external onlyEOA {
        minted += 1;
    }
}
