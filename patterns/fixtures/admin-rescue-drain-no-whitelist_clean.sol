// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// CLEAN: rescueTokens is onlyOwner-gated AND explicitly blacklists the
// user-asset tokens (asset, collateral). The owner can recover unrelated
// airdrops stuck in the contract, but cannot drain depositor principal
// even if the owner key is compromised.
contract VaultRescueClean {
    address public owner;
    address public asset;
    address public collateral;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _asset, address _collateral) {
        owner = msg.sender;
        asset = _asset;
        collateral = _collateral;
    }

    function rescueTokens(address token, uint256 amount) external onlyOwner {
        // User-asset guard: admin cannot rescue depositor-owned balances.
        require(token != asset, "cannot rescue user asset");
        require(token != address(collateral), "cannot rescue collateral");
        IERC20(token).transfer(owner, amount);
    }
}
