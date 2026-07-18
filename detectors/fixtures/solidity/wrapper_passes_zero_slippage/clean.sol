// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IHooks {
    function addLiquidity(uint256[] memory amounts, uint256[] memory minAmounts, uint256 minShares)
        external
        payable
        returns (uint256 shares);
}

/// Clean periphery: forwards the user-supplied per-leg `_minAmounts`
/// AND `_minShares` directly to the inner primitive — both the outer
/// aggregate clamp and the inner per-leg clamp are honoured.
contract CleanZapInPeriphery {
    IHooks public hooks;

    function zapIn(uint256[] calldata _amounts, uint256[] calldata _minAmounts, uint256 _minShares)
        external
        payable
        returns (uint256 sharesOut)
    {
        uint256 len = _amounts.length;
        uint256[] memory balances = new uint256[](len);
        uint256[] memory minAmounts = new uint256[](len);
        for (uint256 i = 0; i < len; ++i) {
            balances[i] = _amounts[i];
            minAmounts[i] = _minAmounts[i]; // user-supplied, NOT zero
        }

        sharesOut = hooks.addLiquidity{value: 0}(balances, minAmounts, _minShares);
    }
}
