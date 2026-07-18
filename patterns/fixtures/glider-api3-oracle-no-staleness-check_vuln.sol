// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IApi3Proxy { function read() external view returns (int224 value, uint32 timestamp); }

contract Api3Vuln {
    IApi3Proxy public proxy;
    constructor(IApi3Proxy p) { proxy = p; }

    function getPrice() external view returns (int224) {
        (int224 value, uint32 timestamp) = proxy.read();
        timestamp; // silence warning, still no validation
        return value;
    }
}
