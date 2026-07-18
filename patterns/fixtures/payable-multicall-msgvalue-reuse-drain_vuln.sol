// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MulticallVuln {
    // VULN: payable multicall dispatches via delegatecall in a loop —
    // msg.value is seen N times by N legs.
    function multicall(bytes[] calldata data) external payable {
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, ) = address(this).delegatecall(data[i]);
            require(ok, "sub call");
        }
    }

    // Sub-function a multicall leg can hit; reads msg.value each iteration.
    function buy(uint256 price) external payable {
        require(msg.value >= price, "underpaid");
        uint256 refund = msg.value - price;
        (bool ok, ) = msg.sender.call{value: refund}("");
        require(ok, "refund");
    }
}
