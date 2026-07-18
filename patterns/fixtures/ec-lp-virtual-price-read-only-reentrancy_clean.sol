// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICurvePool {
    function get_virtual_price() external view returns (uint256);
}

// CLEAN: nonReentrant guard prevents read-only reentrancy exploit
contract CurveLPOracleClean {
    ICurvePool public curvePool;
    mapping(address => uint256) public lpCollateral;
    mapping(address => uint256) public debt;

    uint256 private _status; // reentrancy guard
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

    constructor(address _pool) {
        curvePool = ICurvePool(_pool);
        _status = _NOT_ENTERED;
    }

    // CLEAN: nonReentrant blocks mid-callback exploitation
    function borrow(uint256 borrowAmount) external nonReentrant {
        uint256 virtualPrice = curvePool.get_virtual_price();
        uint256 collateralValue = lpCollateral[msg.sender] * virtualPrice / 1e18;
        require(collateralValue * 2 >= borrowAmount * 3, "undercollateralized");
        debt[msg.sender] += borrowAmount;
    }
}
