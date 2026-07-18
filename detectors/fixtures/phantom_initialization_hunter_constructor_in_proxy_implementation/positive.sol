// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PhantomInitializationProxyImplementationPositive {
    address public owner;
    address public treasury;
    uint256 public marketId;

    constructor(address initialOwner, address initialTreasury) {
        owner = initialOwner;
        treasury = initialTreasury;
    }

    function initialize(uint256 initialMarketId) external {
        marketId = initialMarketId;
    }

    function sweepFees() external view returns (address) {
        require(msg.sender == owner, "not owner");
        return treasury;
    }
}
