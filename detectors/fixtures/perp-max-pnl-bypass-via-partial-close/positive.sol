pragma solidity ^0.8.20;

contract PerpPositionBookPositive {
    uint256 internal constant DIVISION_CONSTANT = 1e10;
    uint256 public maxWinPercent = 5e10;

    struct Trade {
        uint256 margin;
        uint256 payout;
    }

    mapping(uint256 => Trade) internal trades;

    function closePosition(uint256 tradeId, uint256 _percent) external returns (uint256) {
        Trade storage _trade = trades[tradeId];

        uint256 _toMint = _trade.payout * _percent / DIVISION_CONSTANT;
        if (_toMint > _trade.margin * maxWinPercent / DIVISION_CONSTANT) {
            _toMint = _trade.margin * maxWinPercent / DIVISION_CONSTANT;
        }

        _trade.margin = _trade.margin * (DIVISION_CONSTANT - _percent) / DIVISION_CONSTANT;
        _trade.payout = _trade.payout * (DIVISION_CONSTANT - _percent) / DIVISION_CONSTANT;
        return _toMint;
    }
}
