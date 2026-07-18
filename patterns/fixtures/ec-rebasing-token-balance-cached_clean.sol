// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStETH {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function getSharesByPooledEth(uint256) external view returns (uint256);
    function getPooledEthByShares(uint256) external view returns (uint256);
}

// CLEAN: stores stETH shares (not amounts) — immune to rebase
contract StETHVaultClean {
    IStETH public stETH;
    mapping(address => uint256) public depositedShares; // shares, not amounts
    uint256 public totalShares;

    constructor(address _steth) { stETH = IStETH(_steth); }

    // CLEAN: converts amount to shares at deposit time
    function deposit(uint256 amount) external {
        stETH.transferFrom(msg.sender, address(this), amount);
        uint256 sharesReceived = stETH.getSharesByPooledEth(amount);
        depositedShares[msg.sender] += sharesReceived;
        totalShares += sharesReceived;
    }

    // CLEAN: converts shares back to current amount — reflects rebase correctly
    function withdraw() external {
        uint256 shares = depositedShares[msg.sender];
        depositedShares[msg.sender] = 0;
        totalShares -= shares;
        uint256 currentAmount = stETH.getPooledEthByShares(shares);
        stETH.transfer(msg.sender, currentAmount); // correct post-rebase amount
    }
}
