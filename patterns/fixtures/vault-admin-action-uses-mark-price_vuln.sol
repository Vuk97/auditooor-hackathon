// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPerpVenue {
    function getMarkPrice(uint256 marketId) external view returns (uint256);
}

abstract contract Ownable {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
}

/// @title PerpVaultAdminRake (VULN)
/// @notice Admin-gated strategy vault whose fee rake is sized by the
///         *live* perp mark-price. Admin (who may operate a market-maker
///         bot on the same venue) pushes mark-price up for one block,
///         calls collectFees, and withdraws an inflated rake.
contract PerpVaultAdminRake is Ownable {
    IPerpVenue public immutable venue;
    uint256 public immutable marketId;
    uint256 public totalShares;
    uint256 public feeBps = 1000; // 10%
    address public treasury;

    constructor(IPerpVenue _venue, uint256 _marketId, address _treasury) {
        venue = _venue;
        marketId = _marketId;
        treasury = _treasury;
    }

    // BUG: mark-price read with no TWAP / staleness / heartbeat guard.
    // Admin-only function sizes a value-transfer (fee rake to treasury)
    // using the moveable mark-price.
    function collectFees() external onlyOwner {
        uint256 markPrice = venue.getMarkPrice(marketId);
        uint256 grossPnl = totalShares * markPrice;          // naive mark-to-mark
        uint256 rake = (grossPnl * feeBps) / 10_000;
        // admin-controlled rebalance weight uses mark directly
        _sweepTo(treasury, rake);
    }

    // BUG: rebalance sizing also reads raw markPrice — admin can
    // collapse mark-price after this tx to strand user value.
    function rebalance(uint256 targetRatio) external onlyOwner {
        uint256 markPrice = venue.getMarkPrice(marketId);
        uint256 notional = totalShares * markPrice;
        uint256 moveAmount = (notional * targetRatio) / 10_000;
        _sweepTo(treasury, moveAmount);
    }

    function _sweepTo(address to, uint256 amt) internal {
        // transfers ignored for fixture clarity
        (to, amt);
    }
}
