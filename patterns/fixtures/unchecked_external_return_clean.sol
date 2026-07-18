// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UncheckedExternalReturnClean {
    // CLEAN: return value checked
    function sweep(address to, bytes calldata data) external {
        (bool ok, ) = to.call(data);
        require(ok, "call failed");
    }

    function forward(address to) external payable {
        (bool success, ) = to.call{value: msg.value}("");
        require(success, "send failed");
    }
}
