// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// CLEAN: the memory copy is mutated AND written back to storage. NOT flagged.
contract MemCopyWritebackClean {
    struct Config {
        uint256 limit;
        bool enabled;
    }

    Config public config;

    /// Reads config into memory, mutates it, and writes it back to storage.
    function updateLimit(uint256 newLimit) external {
        Config memory c = config;  // memory copy
        c.limit = newLimit;        // field write
        config = c;                // writeback -> storage IS updated -> CLEAN
    }
}
