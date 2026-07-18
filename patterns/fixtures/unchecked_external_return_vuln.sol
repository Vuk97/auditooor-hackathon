// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UncheckedExternalReturnVuln {
    // VULN: .call ignores bool return
    function sweep(address to, bytes calldata data) external {
        to.call(data);  // return value ignored
    }

    function forward(address to) external payable {
        to.call{value: msg.value}("");  // ignored
    }
}
