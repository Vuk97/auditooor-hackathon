// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICurvePool {
    function get_virtual_price() external view returns (uint256);
}

// VULN: reads Curve get_virtual_price() without nonReentrant guard
// Loss ref: JPEG'd ~$11.6M, Alchemix ~$22.6M, July 2023
// https://rekt.news/jpegd-rekt/
// https://chainsecurity.com/heartbreaks-curve-lps/
contract CurveLPOracleVuln {
    ICurvePool public curvePool;
    mapping(address => uint256) public lpCollateral; // in LP tokens
    mapping(address => uint256) public debt;

    constructor(address _pool) { curvePool = ICurvePool(_pool); }

    // VULN: no nonReentrant — can be called mid-remove_liquidity callback
    // During callback: virtual_price is stale-high (pre-removal state)
    function borrow(uint256 borrowAmount) external {
        uint256 virtualPrice = curvePool.get_virtual_price(); // reentrant read possible
        uint256 collateralValue = lpCollateral[msg.sender] * virtualPrice / 1e18;
        require(collateralValue * 2 >= borrowAmount * 3, "undercollateralized");
        debt[msg.sender] += borrowAmount;
    }
}
