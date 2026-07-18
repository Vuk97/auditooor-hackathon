// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// MUTATION BASE for non-vacuity: same shape as MemCopyNoWritebackSuspect.
/// One edit (adding `config = c;`) must flip the detector from FLAGGED to CLEAN.
contract MemCopyMutationBase {
    struct Data {
        uint256 value;
        address owner;
    }

    Data public data;

    /// Memory copy is mutated but NEVER written back. FLAGGED.
    function setValue(uint256 v) external {
        Data memory d = data;  // memory copy
        d.value = v;           // mutate the copy
        // MUTATION_TARGET_WRITEBACK_HERE
    }
}
