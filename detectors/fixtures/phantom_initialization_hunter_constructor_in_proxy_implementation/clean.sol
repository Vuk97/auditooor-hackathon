// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PhantomInitializationProxyImplementationClean {
    address public owner;
    address public treasury;
    uint256 public marketId;

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address initialOwner,
        address initialTreasury,
        uint256 initialMarketId
    ) external {
        owner = initialOwner;
        treasury = initialTreasury;
        marketId = initialMarketId;
    }

    function sweepFees() external view returns (address) {
        require(msg.sender == owner, "not owner");
        return treasury;
    }

    function _disableInitializers() internal pure {}
}
