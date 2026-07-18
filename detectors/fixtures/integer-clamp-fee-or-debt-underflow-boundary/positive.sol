// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IntegerClampFeeOrDebtUnderflowBoundaryPositive {
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
        uint256 lpFee
    ) external returns (uint256) {
        uint256 swapFee = protocolFee + lpFee;
        if (swapFee == 0) {
            return 0;
        }
        uint256 protocolFeeAmount = (amountIn + feeAmount) * protocolFee / PIPS_DENOMINATOR;
        protocolFeesAccrued += protocolFeeAmount;
        return protocolFeeAmount;
    }

    function _currentDebt(uint256 id) public view returns (uint256) {
        Market memory market = markets[id];
        uint256 elapsed = block.timestamp - market.lastDecay;
        uint256 decay = (market.totalDebt * elapsed) / market.decayInterval;
        uint256 lastDebt = market.totalDebt;
        return lastDebt - decay;
    }

    function _updateDebt(uint256 id) external {
        Market storage market = markets[id];
        uint256 elapsed = block.timestamp - market.lastDecay;
        uint256 decay = (market.totalDebt * elapsed) / market.decayInterval;
        market.totalDebt -= decay;
        market.lastDecay = block.timestamp;
    }

    function marketPrice(uint256 id) external view returns (uint256) {
        return _currentDebt(id) + 1e18;
    }
}
