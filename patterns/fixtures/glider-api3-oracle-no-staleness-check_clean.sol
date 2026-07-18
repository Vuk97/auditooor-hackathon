// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IApi3Proxy { function read() external view returns (int224 value, uint32 timestamp); }

contract Api3Clean {
    IApi3Proxy public proxy;
    uint256 public constant MAX_STALENESS = 60;
    constructor(IApi3Proxy p) { proxy = p; }

    function getPrice() external view returns (int224) {
        (int224 value, uint32 timestamp) = proxy.read();
        require(value > 0, "invalid");
        require(block.timestamp - timestamp <= MAX_STALENESS, "stale");
        return value;
    }
}
