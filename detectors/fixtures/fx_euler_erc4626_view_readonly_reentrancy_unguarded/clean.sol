// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract ERC4626 {}

contract FxEulerReadonlyReentrancyClean is ERC4626 {
    uint256 internal _status;
    uint256 internal _cachedAssets;

    error Reentrancy();

    function totalAssets() public view returns (uint256) {
        if (_status == 2) revert Reentrancy();
        return _readAssetsWithGuard();
    }

    function _readAssetsWithGuard() internal view returns (uint256) {
        return _cachedAssets;
    }
}
