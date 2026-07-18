// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ICurvePoolLPValue {
    function get_virtual_price() external view returns (uint256);
    function remove_liquidity(uint256 amount, uint256[2] calldata min_amounts) external;
}

interface ILpToken {
    function totalSupply() external view returns (uint256);
}

contract LpCollateralVaultVuln {
    ICurvePoolLPValue public immutable pool;
    ILpToken public immutable lpToken;

    constructor(ICurvePoolLPValue _pool, ILpToken _lpToken) {
        pool = _pool;
        lpToken = _lpToken;
    }

    // VULN: reads get_virtual_price() with no Curve reentrancy sentinel and
    // no local nonReentrant. An attacker re-enters from within
    // pool.remove_liquidity (native-eth path) and observes an inflated price.
    function quoteLpPriceUsd() external view returns (uint256) {
        uint256 vp = pool.get_virtual_price();
        return (vp * 1e18) / lpToken.totalSupply();
    }

    function redeem(uint256 shares) external {
        // Unsafe: quote relies on manipulable virtual price.
        uint256 lpPrice = pool.get_virtual_price();
        uint256 payout = (shares * lpPrice) / 1e18;
        payable(msg.sender).transfer(payout);
    }
}
