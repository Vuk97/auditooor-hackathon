// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MulticallClean {
    // CLEAN: assert msg.value == 0 — users cannot reuse one payment.
    function multicall(bytes[] calldata data) external payable {
        require(msg.value == 0, "no value in multicall");
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, ) = address(this).delegatecall(data[i]);
            require(ok, "sub call");
        }
    }

    function buy(uint256 price) external payable {
        require(msg.value >= price, "underpaid");
        uint256 refund = msg.value - price;
        (bool ok, ) = msg.sender.call{value: refund}("");
        require(ok, "refund");
    }
}
