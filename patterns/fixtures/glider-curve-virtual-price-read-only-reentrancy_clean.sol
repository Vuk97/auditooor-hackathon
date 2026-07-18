// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ICurvePoolLPValue {
    function get_virtual_price() external view returns (uint256);
    function remove_liquidity(uint256 amount, uint256[2] calldata min_amounts) external;
}

interface ILpToken {
    function totalSupply() external view returns (uint256);
}

abstract contract ReentrancyGuard {
    uint256 private _status = 1;
    modifier nonReentrant() {
        require(_status == 1, "REENTRANT");
        _status = 2;
        _;
        _status = 1;
    }
}

contract LpCollateralVaultClean is ReentrancyGuard {
    ICurvePoolLPValue public immutable pool;
    ILpToken public immutable lpToken;

    constructor(ICurvePoolLPValue _pool, ILpToken _lpToken) {
        pool = _pool;
        lpToken = _lpToken;
    }

    // CLEAN: sentinel remove_liquidity(0, [0,0]) reverts if the pool is
    // locked (i.e., we are mid-Curve-operation), blocking read-only
    // reentrancy. Additionally nonReentrant prevents local re-entry.
    function quoteLpPriceUsd() external nonReentrant returns (uint256) {
        uint256[2] memory zeros;
        pool.remove_liquidity(0, zeros);
        uint256 vp = pool.get_virtual_price();
        return (vp * 1e18) / lpToken.totalSupply();
    }

    function redeem(uint256 shares) external nonReentrant {
        uint256[2] memory zeros;
        pool.remove_liquidity(0, zeros);
        uint256 lpPrice = pool.get_virtual_price();
        uint256 payout = (shares * lpPrice) / 1e18;
        payable(msg.sender).transfer(payout);
    }
}
