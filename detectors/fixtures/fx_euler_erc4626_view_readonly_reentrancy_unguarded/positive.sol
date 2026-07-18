// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract ERC4626 {}

contract FxEulerReadonlyReentrancyPositive is ERC4626 {
    uint256 internal _status;
    uint256 internal _cachedAssets;

    function totalAssets() public view returns (uint256) {
        return _readAssetsWithoutViewGuard();
    }

    function _readAssetsWithoutViewGuard() internal view returns (uint256) {
        return _cachedAssets;
    }
}
