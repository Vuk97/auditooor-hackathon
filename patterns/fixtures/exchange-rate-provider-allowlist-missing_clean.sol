// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRateProvider { function rate() external view returns (uint256); }

contract ExchangeRateProviderAllowlistMissingClean {
    mapping(address => uint256) public lastRate;
    mapping(address => address) public allowedProviders;

    function setProvider(address asset, address provider) external {
        allowedProviders[asset] = provider;
    }

    function updateRate(address asset, address provider) external {
        require(allowedProviders[asset] == provider, "unbound provider");
        lastRate[asset] = IRateProvider(provider).rate();
    }
}
