// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library ClampMath {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}

contract IntegerClampFeeOrDebtUnderflowBoundaryClean {
    uint256 internal constant PIPS_DENOMINATOR = 1_000_000;
    uint256 public protocolFeesAccrued;

    struct Market {
        uint256 totalDebt;
        uint256 lastDecay;
        uint256 decayInterval;
    }

    mapping(uint256 => Market) public markets;

    function openMarket(uint256 id, uint256 initialDebt, uint256 decayInterval) external {
        markets[id] = Market({
            totalDebt: initialDebt,
            lastDecay: block.timestamp,
            decayInterval: decayInterval
        });
    }

    function quote(
        uint256 amountIn,
        uint256 feeAmount,
        uint256 protocolFee,
        uint256 swapFee
    ) external returns (uint256) {
        return swapStep(amountIn, feeAmount, protocolFee, swapFee);
    }

    function swapStep(
        uint256 amountIn,
        uint256 feeAmount,
        uint256 protocolFee,
        uint256 swapFee
    ) internal returns (uint256) {
        uint256 protocolFeeAmount;
        if (swapFee == protocolFee) {
            protocolFeeAmount = feeAmount;
        } else {
            protocolFeeAmount = (amountIn + feeAmount) * protocolFee / PIPS_DENOMINATOR;
        }
        protocolFeesAccrued += protocolFeeAmount;
        return protocolFeeAmount;
    }

    function quoteProtocolFeeOnly(
        uint256 amountIn,
        uint256 feeAmount,
        uint256 protocolFee
    ) external pure returns (uint256) {
        return (amountIn + feeAmount) * protocolFee / PIPS_DENOMINATOR;
    }

    function _currentDebt(uint256 id) public view returns (uint256) {
        Market memory market = markets[id];
        uint256 elapsed = block.timestamp - market.lastDecay;
        uint256 decay = (market.totalDebt * elapsed) / market.decayInterval;
        uint256 lastDebt = market.totalDebt;
        return decay > lastDebt ? 0 : lastDebt - decay;
    }

    function _updateDebt(uint256 id) external {
        Market storage market = markets[id];
        uint256 elapsed = block.timestamp - market.lastDecay;
        uint256 decay = (market.totalDebt * elapsed) / market.decayInterval;
        uint256 applied = ClampMath.min(market.totalDebt, decay);
        market.totalDebt -= applied;
        market.lastDecay = block.timestamp;
    }

    function marketPrice(uint256 id) external view returns (uint256) {
        return _currentDebt(id) + 1e18;
    }
}
