// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IHooks {
    function addLiquidity(uint256[] memory amounts, uint256[] memory minAmounts, uint256 minShares)
        external
        payable
        returns (uint256 shares);
}

/// Vulnerable periphery: builds a fresh zero `uint256[]` and passes it
/// as `minAmounts` to the inner `_hooks.addLiquidity(...)` call, plus a
/// literal `0` as `minShares`. Outer-only `_minShares` clamp leaves
/// per-leg imbalance unprotected (Revert Cantina #15 shape).
contract VulnerableZapInPeriphery {
    IHooks public hooks;

    function zapIn(uint256[] calldata _amounts, uint256 _minShares) external payable returns (uint256 sharesOut) {
        uint256 len = _amounts.length;
        uint256[] memory balances = new uint256[](len);
        for (uint256 i = 0; i < len; ++i) {
            balances[i] = _amounts[i];
        }

        // VULN: zero-array slippage + literal-zero minShares passed
        // to the inner sibling-primitive call.
        uint256[] memory minAmounts = new uint256[](len);
        sharesOut = hooks.addLiquidity{value: 0}(balances, minAmounts, 0);

        require(sharesOut >= _minShares, "MIN_SHARES");
    }
}
