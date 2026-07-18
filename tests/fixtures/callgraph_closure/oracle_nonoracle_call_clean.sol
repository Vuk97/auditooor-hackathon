// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVault {
    function read() external view returns (uint256);   // generic, NOT an oracle
    function quote() external view returns (uint256);   // generic, NOT an oracle
    function current() external view returns (uint256); // generic, NOT an oracle
}

/// A try/catch wrapping NON-oracle external calls under generic method names
/// (`read`/`quote`/`current`) that were dropped from the oracle-read name set.
/// Even though the catch SWALLOWS, these are not oracle reads, so there is no
/// stale-price economic risk to flag. -> NOT flagged.
/// (Regression for the W2 generic-name false-positive fix.)
contract NonOracleSwallow {
    IVault public vault;
    uint256 public value;

    function refresh() external {
        try vault.read() returns (uint256 v) {
            value = v;
        } catch {
            // swallow: but `read()` is not an oracle read
        }
    }

    function refreshQuote() external {
        try vault.quote() returns (uint256 v) {
            value = v;
        } catch {
            // swallow: but `quote()` is not an oracle read
        }
    }

    function refreshCurrent() external {
        try vault.current() returns (uint256 v) {
            value = v;
        } catch {
            // swallow: but `current()` is not an oracle read
        }
    }
}
