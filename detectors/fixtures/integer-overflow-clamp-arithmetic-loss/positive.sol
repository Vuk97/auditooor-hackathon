// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICurveToken {
    function mint(address to, uint256 amount) external;
}

contract IntegerOverflowClampArithmeticLossPositive {
    uint256 internal constant PIPS_DENOMINATOR = 1_000_000;
    uint256 public protocolFeesAccrued;
    uint256 public step = 1e15;
    uint256 public theta = 1e18;
    uint256 public curveK = 5e17;
    uint256 public reserveBase;
    ICurveToken public token;

    struct Market {
        uint256 totalDebt;
        uint256 lastDecay;
        uint256 decayInterval;
        uint256 price;
    }

    mapping(uint256 => Market) public markets;

    constructor(ICurveToken curveToken) {
        token = curveToken;
    }

    function openMarket(uint256 id, uint256 initialDebt, uint256 decayInterval, uint256 price) external {
        markets[id] = Market({
            totalDebt: initialDebt,
            lastDecay: block.timestamp,
            decayInterval: decayInterval,
            price: price
        });
    }

    function quote(uint256 amountIn, uint256 feeAmount, uint256 protocolFee) external returns (uint256) {
        return swapStep(amountIn, feeAmount, protocolFee);
    }

    function swapStep(uint256 amountIn, uint256 feeAmount, uint256 protocolFee) internal returns (uint256) {
        uint256 protocolFeeAmount = (amountIn + feeAmount) * protocolFee / PIPS_DENOMINATOR;
        protocolFeesAccrued += protocolFeeAmount;
        return protocolFeeAmount;
    }

    function _currentDebt(uint256 id) public view returns (uint256) {
        Market memory market = markets[id];
        uint256 secondsSinceDecay = block.timestamp - market.lastDecay;
        uint256 decay = (market.totalDebt * secondsSinceDecay) / market.decayInterval;
        uint256 lastDebt = market.totalDebt;
        return lastDebt - decay;
    }

    function _updateDebt(uint256 id) external {
        Market storage market = markets[id];
        uint256 secondsSinceDecay = block.timestamp - market.lastDecay;
        uint256 decay = (market.totalDebt * secondsSinceDecay) / market.decayInterval;
        market.totalDebt -= decay;
        market.lastDecay = block.timestamp;
    }

    function marketPrice(uint256 id) external view returns (uint256) {
        uint256 debt = _currentDebt(id);
        return markets[id].price + debt;
    }

    function buy(uint256 desired) external payable returns (uint256 cost) {
        unchecked {
            cost = desired * step / 1e18;
        }
        require(msg.value >= cost, "underpaid");
        reserveBase += cost;
        token.mint(msg.sender, desired);
    }

    function purchase(uint256 amount) external {
        uint256 toMint;
        unchecked {
            toMint = amount * theta;
        }
        reserveBase += amount;
        token.mint(msg.sender, toMint);
    }
}
