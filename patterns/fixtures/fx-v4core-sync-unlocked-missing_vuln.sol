// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.20;

// Fixture: sync() callable while locked (no onlyWhenUnlocked modifier) — ToB L01.
// Source: Uniswap/v4-core@4dc48bb (ToB L01)
// Vulnerability: If sync() can be called while the pool is locked (between unlock/callback),
// an attacker can manipulate the synced currency reserves during a callback, desynchronizing
// the expected vs. actual balance. Combined with settle(), this enables theft of tokens by
// making the pool believe fewer tokens were owed than were actually taken.

contract Fix {
    bool private _locked;
    address private _syncedCurrency;
    uint256 private _syncedReserves;

    error AlreadyUnlocked();

    modifier onlyWhenUnlocked() {
        require(_locked, "not unlocked");
        _;
    }

    function unlock(bytes calldata data) external returns (bytes memory) {
        require(!_locked, "already unlocked");
        _locked = true;
        // ... callback
        _locked = false;
        return data;
    }

    // VULNERABLE: missing onlyWhenUnlocked modifier
    // Can be called by anyone even when pool is locked, corrupting currency reserve state
    function sync(address currency) external {
        _syncedCurrency = currency;
        _syncedReserves = _balanceOf(currency);
    }

    function settle() external onlyWhenUnlocked returns (uint256 paid) {
        address currency = _syncedCurrency;
        uint256 reservesBefore = _syncedReserves;
        uint256 reservesNow = _balanceOf(currency);
        paid = reservesNow - reservesBefore; // can underflow if sync was called mid-tx
        _syncedCurrency = address(0);
    }

    function _balanceOf(address token) internal view returns (uint256) {
        return token.balance; // simplified
    }
}
