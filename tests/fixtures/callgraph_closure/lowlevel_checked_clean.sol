// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// NOT FLAGGED: the `.call` success flag is captured and consumed by a require.
contract LowLevelCheckedClean {
    function forward(address to, bytes calldata data) external {
        (bool ok, ) = to.call(data);
        require(ok, "low-level call failed");
    }
}
