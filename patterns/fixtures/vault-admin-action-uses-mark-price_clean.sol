// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPerpVenue {
    function getMarkPrice(uint256 marketId) external view returns (uint256);
    function getTwapPrice(uint256 marketId, uint32 window) external view returns (uint256);
}

interface IChainlink {
    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound
    );
}

abstract contract Ownable {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
}

/// @title PerpVaultAdminRakeSafe (CLEAN)
/// @notice Admin-gated rake/rebalance that:
///   (a) uses a TWAP window instead of live mark-price,
///   (b) cross-checks a Chainlink oracle with a heartbeat / staleness guard.
/// This removes the single-block mark-price-manipulation surface.
contract PerpVaultAdminRakeSafe is Ownable {
    IPerpVenue public immutable venue;
    IChainlink public immutable oracle;
    uint256 public immutable marketId;
    uint256 public totalShares;
    uint256 public feeBps = 1000;
    address public treasury;

    uint32  public constant TWAP_WINDOW = 30 minutes;
    uint256 public constant MAX_STALE   = 1 hours;          // heartbeat
    uint256 public constant MAX_DEV_BPS = 200;              // 2% oracle-vs-twap band

    constructor(IPerpVenue _venue, IChainlink _oracle, uint256 _marketId, address _treasury) {
        venue = _venue; oracle = _oracle; marketId = _marketId; treasury = _treasury;
    }

    function _refPrice() internal view returns (uint256) {
        // TWAP instead of raw markPrice — intentionally not calling getMarkPrice.
        uint256 twap = venue.getTwapPrice(marketId, TWAP_WINDOW);

        // Chainlink staleness / heartbeat guard
        (, int256 ans, , uint256 updatedAt, ) = oracle.latestRoundData();
        require(ans > 0, "bad oracle answer");
        require(block.timestamp - updatedAt <= MAX_STALE, "oracle stale");
        uint256 ocl = uint256(ans);

        // Divergence band — if oracle and venue-TWAP disagree, bail.
        uint256 diff = twap > ocl ? twap - ocl : ocl - twap;
        require((diff * 10_000) / ocl <= MAX_DEV_BPS, "twap/oracle divergence");
        return twap;
    }

    function collectFees() external onlyOwner {
        uint256 ref = _refPrice();
        uint256 grossPnl = totalShares * ref;
        uint256 rake = (grossPnl * feeBps) / 10_000;
        _sweepTo(treasury, rake);
    }

    function rebalance(uint256 targetRatio) external onlyOwner {
        uint256 ref = _refPrice();
        uint256 notional = totalShares * ref;
        uint256 moveAmount = (notional * targetRatio) / 10_000;
        _sweepTo(treasury, moveAmount);
    }

    function _sweepTo(address to, uint256 amt) internal { (to, amt); }
}
