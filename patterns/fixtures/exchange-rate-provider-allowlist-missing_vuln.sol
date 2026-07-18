// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRateProvider { function rate() external view returns (uint256); }

contract ExchangeRateProviderAllowlistMissingVuln {
    mapping(address => uint256) public lastRate;

    function updateRate(address asset, address provider) external {
        // VULN: no check that `provider` is the canonical rate provider for `asset`.
        lastRate[asset] = IRateProvider(provider).rate();
    }
}
