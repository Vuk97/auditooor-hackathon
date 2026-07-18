// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// CLEAN: internal accounting tracker — not raw balanceOf
contract DonationVaultClean {
    IERC20 public token;
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 private _totalAssets; // internal accounting only

    constructor(address _token) { token = IERC20(_token); }

    // CLEAN: returns internal tracker — ignores direct donations
    function totalAssets() external view returns (uint256) {
        return _totalAssets;
    }

    function pricePerShare() external view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return _totalAssets * 1e18 / totalShares; // donation-resistant
    }

    function deposit(uint256 assets) external {
        uint256 minted = totalShares == 0 ? assets : assets * totalShares / _totalAssets;
        token.transferFrom(msg.sender, address(this), assets);
        _totalAssets += assets; // only increases via deposit()
        shares[msg.sender] += minted;
        totalShares += minted;
    }
}
