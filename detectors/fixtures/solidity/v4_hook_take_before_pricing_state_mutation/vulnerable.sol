// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IPoolManager {
    function take(address currency, address recipient, uint256 amount) external;
    function burn(address from, uint256 id, uint256 amount) external;
}

interface IUnlockCallback {
    function unlockCallback(bytes calldata data) external returns (bytes memory);
}

/// Vulnerable hook: takes funds to user BEFORE updating reserves[].
/// Recipient can call PoolManager.swap() under onlyWhenUnlocked and
/// trade against stale reserves (Cantina #29).
contract VulnerableHook is IUnlockCallback {
    IPoolManager public poolManager;
    uint256[] public reserves;

    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        uint256 action = abi.decode(data, (uint256));
        if (action == 1) {
            _handleRemoveLiquidityCallback(data);
        }
        return "";
    }

    function _handleRemoveLiquidityCallback(bytes calldata data) internal {
        (, uint256 shares, uint256[] memory amounts, address sender) =
            abi.decode(data, (uint256, uint256, uint256[], address));

        for (uint256 i = 0; i < amounts.length; ++i) {
            address currency = address(0);
            poolManager.burn(address(this), uint256(uint160(currency)), amounts[i]);
            // VULN: take BEFORE reserves[i] -= amounts[i]
            poolManager.take(currency, sender, amounts[i]);
            reserves[i] -= amounts[i];
        }
        // unused: shares
        shares;
    }
}
