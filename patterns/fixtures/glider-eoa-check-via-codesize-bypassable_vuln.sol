// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EOACheckVuln {
    mapping(address => bool) public minted;

    function _checkEOA() internal view {
        require(msg.sender.code.length == 0, "only EOA");
    }

    function mint() external {
        _checkEOA();
        require(!minted[msg.sender], "already");
        minted[msg.sender] = true;
    }
}