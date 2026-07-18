// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// CLEAN: the memory copy is made but NEVER mutated (read-only use). NOT flagged.
contract MemCopyNoMutationClean {
    struct Config {
        uint256 limit;
        bool enabled;
    }

    Config public config;

    /// Reads config into memory for read-only access. The copy is never mutated.
    /// CLEAN (no lost write).
    function getLimit() external view returns (uint256) {
        Config memory c = config;  // memory copy, read-only
        return c.limit;            // pure read, no mutation -> CLEAN
    }
}
