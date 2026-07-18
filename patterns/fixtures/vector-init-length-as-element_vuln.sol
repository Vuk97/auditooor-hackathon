// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// VULN: uses new uint256[](1) then stores the *length* into slot 0.
// Downstream loops reading `out[i]` for i in [0, len) will OOB-revert
// once len > 1 — same semantic bug as `vec![len]` in Rust.
contract BatchProcessorVuln {
    function plan(uint256 totalLen) external pure returns (uint256[] memory) {
        uint256[] memory out = new uint256[](1);
        out[0] = totalLen; // BUG: capacity is 1 but we expect `totalLen` elements
        return out;
    }

    function dispatch(bytes[] calldata payloads) external pure returns (bytes32[] memory) {
        uint256 numPayloads = payloads.length;
        bytes32[] memory digests = new bytes32[](1);
        digests[0] = bytes32(numPayloads); // BUG: length stored as element
        for (uint256 i = 0; i < numPayloads; ++i) {
            digests[i] = keccak256(payloads[i]); // OOB-reverts for i >= 1
        }
        return digests;
    }
}
