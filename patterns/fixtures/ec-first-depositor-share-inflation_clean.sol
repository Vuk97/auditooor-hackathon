// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// CLEAN: virtual offset prevents inflation attack
// OpenZeppelin ERC-4626 approach: add virtual shares/assets offset
contract VaultInflationClean {
    IERC20 public token;
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 internal _totalAssets; // internal accounting — not raw balanceOf

    uint256 public constant VIRTUAL_OFFSET = 1e3; // virtual shares/assets

    constructor(address _token) { token = IERC20(_token); }

    // CLEAN: returns internal accounting + virtual offset — donation-resistant
    function totalAssets() public view returns (uint256) {
        return _totalAssets + VIRTUAL_OFFSET;
    }

    function _totalSharesWithOffset() internal view returns (uint256) {
        return totalShares + VIRTUAL_OFFSET;
    }

    // CLEAN: virtual offset makes first-depositor inflation economically infeasible
    function deposit(uint256 assets) external returns (uint256 minted) {
        token.transferFrom(msg.sender, address(this), assets);
        minted = assets * _totalSharesWithOffset() / totalAssets();
        _totalAssets += assets;
        shares[msg.sender] += minted;
        totalShares += minted;
    }
}
