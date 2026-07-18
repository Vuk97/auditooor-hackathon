// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GasLeftClean {
    uint256 constant MIN_GAS = 100_000;

    // CLEAN: asserts enough gas remaining before the call
    function forwardCall(address target, bytes calldata data) external returns (bool) {
        require(gasleft() >= MIN_GAS * 64 / 63, "insufficient gas");
        (bool ok, ) = target.call{gas: gasleft()}(data);
        require(ok, "subcall failed");
        return ok;
    }
}
