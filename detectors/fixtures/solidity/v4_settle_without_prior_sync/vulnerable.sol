// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IPoolManager {
    function settle() external payable returns (uint256);
    function sync(address currency) external;
    function mint(address to, uint256 id, uint256 amount) external;
}

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external;
}

/// VULN: native branch calls settle{value:} without sync(address(0)).
/// ERC20 sibling branch calls sync(currency); settle() — proves the
/// team knows sync is required (sibling-branch asymmetry / L26).
contract VulnerableSettle {
    IPoolManager public poolManager;

    function _handleAddLiquidityCallback(address[] memory currencies, uint256[] memory amounts, address sender) internal {
        for (uint256 i = 0; i < currencies.length; ++i) {
            address currency = currencies[i];
            if (currency == address(0)) {
                // VULN: no sync(address(0)) here
                poolManager.settle{value: amounts[i]}();
            } else {
                poolManager.sync(currency);
                IERC20(currency).transferFrom(sender, address(poolManager), amounts[i]);
                poolManager.settle();
            }
            poolManager.mint(address(this), uint256(uint160(currency)), amounts[i]);
        }
    }
}
