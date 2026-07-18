pragma solidity ^0.8.20;

contract PerpPositionBookClean {
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
        uint256 _partialMargin = _trade.margin * _percent / DIVISION_CONSTANT;
        if (_toMint > _partialMargin * maxWinPercent / DIVISION_CONSTANT) {
            _toMint = _partialMargin * maxWinPercent / DIVISION_CONSTANT;
        }

        _trade.margin = _trade.margin - _partialMargin;
        _trade.payout = _trade.payout * (DIVISION_CONSTANT - _percent) / DIVISION_CONSTANT;
        return _toMint;
    }
}
