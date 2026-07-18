// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReturnBombLowLevelCallsCopyingBytesSafe {
    address public target;

    function setTarget(address target_) external {
        target = target_;
    }

    function collect(address callee, bytes calldata payload) external returns (bytes memory) {
        (bool ok, bytes memory ret) = callee.call(payload);
        require(ok, "call failed");
        require(ret.length <= 64, "return-bomb bound");
        return ret;
    }
}
