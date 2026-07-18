// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract LendingRepayPoolClean {
    uint256 internal treasuryShares;
    uint256 internal lpTokenSupply;

    function repayCreditAccount(uint256 debt, uint256 profit, uint256 loss) external {
        lpTokenSupply += debt;

        if (profit > 0) {
            _mintTreasury(profit);
        }

        if (loss > 0) {
            _burnTreasury(loss);
        }
    }

    function _mintTreasury(uint256 amount) internal {
        treasuryShares += amount;
    }

    function _burnTreasury(uint256 amount) internal {
        treasuryShares -= amount;
    }
}
