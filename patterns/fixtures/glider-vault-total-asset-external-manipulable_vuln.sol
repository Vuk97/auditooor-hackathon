// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICurvePool {
    function get_virtual_price() external view returns (uint256);
}

interface IERC20 { function balanceOf(address) external view returns (uint256); }

contract Vault4626Vuln {
    ICurvePool public pool;
    IERC20 public lp;

    // VULN: depends on live virtual_price, which is flash-manipulable
    function totalAssets() external view returns (uint256) {
        uint256 bal = lp.balanceOf(address(this));
        return (bal * pool.get_virtual_price()) / 1e18;
    }
}
