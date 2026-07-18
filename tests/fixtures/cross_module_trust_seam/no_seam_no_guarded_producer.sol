// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Case 3 (no guarded producer -> 0).
// The state var `val` is written ONLY by an unguarded setter: there is no
// trust boundary to bypass (nobody validated V), so condition (a) fails and
// NO seam is emitted even though the consumer is a permissionless reader.
contract Vault {
    uint256 public val; // V (no guarded producer)

    // UNGUARDED producer (no caller-identity guard anywhere in closure).
    function setVal(uint256 newVal) external {
        val = newVal;
    }

    // UNGUARDED consumer sink.
    function readVal() external view returns (uint256) {
        return val + 1;
    }
}
