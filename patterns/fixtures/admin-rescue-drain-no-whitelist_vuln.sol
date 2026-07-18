// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// VULN: rescueTokens is onlyOwner-gated but lacks a blacklist of the
// user-asset token. A compromised owner can pass `asset` and transfer the
// entire depositor principal. The function advertises itself as "rescuing
// stuck tokens" but can drain user funds.
contract VaultRescueVuln {
    address public owner;
    address public asset;        // ← user-deposited token (e.g., USDC)
    address public collateral;   // ← secondary user-asset slot

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
        // No blacklist — token == asset is accepted.
        IERC20(token).transfer(owner, amount);
    }
}
