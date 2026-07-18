// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: lending helper hardcodes USDC/USDT/DAI at 1:1 (returns 1e18) instead
// of consulting an oracle. A depeg event (UST 2022, USDC SVB 2023) makes
// every collateral valuation wrong and the protocol is instantaneously
// under-collateralised.
contract StablePegPriceVuln {
    address public immutable USDC;
    address public immutable USDT;
    address public immutable DAI;

    constructor(address _usdc, address _usdt, address _dai) {
        USDC = _usdc;
        USDT = _usdt;
        DAI = _dai;
    }

    // Values any supported stablecoin at par without checking a live feed.
    function getStablePrice(address token) external pure returns (uint256) {
        // Trust-the-peg: returns 1e18 for every recognised stablecoin.
        if (token != address(0)) {
            return 1e18;
        }
        return 0;
    }

    function valueStableCollateral(address token, uint256 amount)
        external
        pure
        returns (uint256)
    {
        // Another par-peg codepath: treat every stable as exactly $1 per unit.
        return 1e18 * amount;
    }
}
