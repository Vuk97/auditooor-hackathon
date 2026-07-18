// SPDX-License-Identifier: MIT
// Fixture: borrow-can-drain-protocol-reserves — CLEAN
// Detector MUST NOT fire on this contract.
//
// Mitigation: the borrow cap subtracts reserves from available balance
// before checking against debtSharesTotal. The protocol safety cushion
// is never at risk even if totalLent would otherwise permit the borrow.
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract LendingVaultClean {
    // Core accounting
    uint256 public totalLent;       // total debt outstanding
    uint256 public totalDeposited;   // total user deposits
    uint256 public reserves;         // protocol safety cushion (set-aside)
    uint256 public debtSharesTotal;   // share-based debt tracking

    address public underlying;
    address public owner;

    // Internal view: available = balance - reserves
    function _getAvailableBalance() internal view returns (uint256) {
        return IERC20(underlying).balanceOf(address(this)) - reserves;
    }

    // CLEAN: borrow correctly subtracts reserves from the balance before
    // checking the debt cap. The protocol safety cushion (reserves) is
    // protected even when debtSharesTotal <= totalLent would permit borrowing.
    function borrow(uint256 shares) external {
        // Compute available = balance - reserves  ← this is the safe pattern
        uint256 available = _getAvailableBalance();

        // debtSharesTotal checked against totalLent BUT available already
        // has reserves subtracted, so reserves are never at risk.
        require(debtSharesTotal + shares <= _convertToShares(totalLent), "cap reached");
        require(available >= _convertToAssets(shares), "insufficient balance");

        debtSharesTotal += shares;
        IERC20(underlying).transfer(msg.sender, _convertToAssets(shares));
    }

    // Helper: converts shares to underlying assets
    function _convertToShares(uint256 assets) internal view returns (uint256) {
        return assets;
    }

    function _convertToAssets(uint256 shares) internal view returns (uint256) {
        return shares;
    }
}
