// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// FLAGGED: a MEMORY copy of a storage struct is mutated but NEVER written back.
/// The state update is silently lost.
contract MemCopyNoWritebackSuspect {
    struct Config {
        uint256 limit;
        bool enabled;
    }

    Config public config;

    /// Reads config into a MEMORY local, mutates the local, but never writes back
    /// to `config`. The increment of `config.limit` is silently lost.
    function updateLimit(uint256 newLimit) external {
        Config memory c = config;  // memory copy of storage struct
        c.limit = newLimit;        // field write on the MEMORY copy
        // BUG: `config = c;` is missing -> the mutation is never persisted
    }
}
