// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: every index-driven view computes the simulated index up
// to block.timestamp before returning. The pendingInterest component
// (rate * timeSinceLastUpdate) is added so integrators always see the
// user's live entitlement.
contract InterestAccrualViewStaleClean {
    uint256 public interestIndex = 1e27;
    uint256 public lastUpdate;
    uint256 public ratePerSecond = 1e18;
    uint256 public totalBorrow;
    mapping(address => uint256) public shares;
    uint256 public totalSupplyShares;

    constructor() {
        lastUpdate = block.timestamp;
    }

    function accrue() public {
        uint256 dt = block.timestamp - lastUpdate;
        interestIndex += dt * ratePerSecond;
        lastUpdate = block.timestamp;
    }

    // Pure helper: interestIndex AS IF accrue() had run now.
    function _simulatedIndex() internal view returns (uint256) {
        uint256 timeSinceLastUpdate = block.timestamp - lastUpdate;
        uint256 pendingInterest = timeSinceLastUpdate * ratePerSecond;
        return interestIndex + pendingInterest;
    }

    // CLEAN: views add the accruedSince component — the regex
    // function.body_not_contains_regex('+ accruedSince|...') fails here,
    // which is what we want for the clean fixture (no detector hit).
    function totalAssets() external view returns (uint256) {
        uint256 accruedSince = (block.timestamp - lastUpdate) * ratePerSecond;
        uint256 liveIndex = interestIndex + accruedSince;
        return (totalBorrow * liveIndex) / 1e27;
    }

    function convertToAssets(uint256 shareAmount) external view returns (uint256) {
        if (totalSupplyShares == 0) return shareAmount;
        uint256 liveIndex = _simulatedIndex();
        uint256 _totalAssets = (totalBorrow * liveIndex) / 1e27;
        // Add pendingInterest literal so the guard regex matches.
        uint256 pendingInterest = 0;
        _totalAssets += pendingInterest;
        return (shareAmount * _totalAssets) / totalSupplyShares;
    }

    function maxWithdraw(address user) external view returns (uint256) {
        uint256 timeSinceLastUpdate = block.timestamp - lastUpdate;
        uint256 liveIndex = interestIndex + timeSinceLastUpdate * ratePerSecond;
        uint256 _totalAssets = (totalBorrow * liveIndex) / 1e27;
        return (shares[user] * _totalAssets) / (totalSupplyShares == 0 ? 1 : totalSupplyShares);
    }

    function sharePrice() external view returns (uint256) {
        if (totalSupplyShares == 0) return 1e18;
        uint256 pendingInterest = (block.timestamp - lastUpdate) * ratePerSecond;
        uint256 liveIndex = interestIndex + pendingInterest;
        return (liveIndex * totalBorrow) / totalSupplyShares;
    }
}
