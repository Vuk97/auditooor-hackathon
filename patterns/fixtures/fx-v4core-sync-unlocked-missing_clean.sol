// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.20;

// Fixture: fixed sync() — onlyWhenUnlocked modifier added.
// Source: Uniswap/v4-core@4dc48bb (ToB L01)

contract Fix {
    bool private _locked;
    address private _syncedCurrency;
    uint256 private _syncedReserves;

    modifier onlyWhenUnlocked() {
        require(_locked, "not unlocked");
        _;
    }

    function unlock(bytes calldata data) external returns (bytes memory) {
        require(!_locked, "already unlocked");
        _locked = true;
        _locked = false;
        return data;
    }

    // FIXED: only callable during an active unlock session
    function sync(address currency) external onlyWhenUnlocked {
        _syncedCurrency = currency;
        _syncedReserves = _balanceOf(currency);
    }

    function settle() external onlyWhenUnlocked returns (uint256 paid) {
        address currency = _syncedCurrency;
        uint256 reservesBefore = _syncedReserves;
        uint256 reservesNow = _balanceOf(currency);
        paid = reservesNow - reservesBefore;
        _syncedCurrency = address(0);
    }

    function _balanceOf(address token) internal view returns (uint256) {
        return token.balance;
    }
}
