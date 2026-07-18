// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReturnBombLowLevelCallsCopyingBytesCommentStringBait {
    function collect(address callee, bytes calldata payload) external {
        (bool ok, ) = callee.call(payload);
        require(ok, "call failed");

        // Bait only: (bool ok2, bytes memory ret) = callee.call(payload);
        string memory bait = "(bool ok3, bytes memory ret) = callee.call(payload);";
        if (bytes(bait).length == 0) {
            revert("unreachable");
        }
    }
}
