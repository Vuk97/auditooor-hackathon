// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC4626 { function totalAssets() external view returns (uint256); }

contract VaultVuln is IERC4626 {
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

    /// VULN: burns shares even if assets==0 from rounding.
    function redeem(uint256 shares, address, address owner) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        _burn(owner, shares);
        // would transfer 0 assets here
    }
}
