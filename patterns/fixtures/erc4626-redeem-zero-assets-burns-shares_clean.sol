// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC4626 { function totalAssets() external view returns (uint256); }

contract VaultClean is IERC4626 {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    uint256 public _totalAssets;

    function totalAssets() external view returns (uint256) { return _totalAssets; }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        if (totalSupply == 0) return shares;
        return (shares * _totalAssets) / totalSupply;
    }

    function previewRedeem(uint256 shares) external view returns (uint256) { return convertToAssets(shares); }

    function _burn(address a, uint256 s) internal { balanceOf[a] -= s; totalSupply -= s; }

    function redeem(uint256 shares, address, address owner) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        require(assets > 0, "ZERO_ASSETS");
        _burn(owner, shares);
    }
}
