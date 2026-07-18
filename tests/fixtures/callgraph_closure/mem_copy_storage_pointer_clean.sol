// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// CLEAN: a `storage` pointer - NOT a memory copy - so writes go directly to
/// storage. The pointer IS the storage reference; no writeback needed. NOT flagged.
contract MemCopyStoragePointerClean {
    struct Config {
        uint256 limit;
        bool enabled;
    }

    Config public config;

    /// Uses a storage POINTER (not a memory copy). Mutations go directly to
    /// the storage slot - no writeback needed. CLEAN.
    function updateLimit(uint256 newLimit) external {
        Config storage c = config;  // storage pointer, NOT a copy
        c.limit = newLimit;         // direct write to storage -> CLEAN
    }
}
