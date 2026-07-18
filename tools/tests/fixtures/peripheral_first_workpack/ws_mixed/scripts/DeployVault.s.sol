// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../src/CoreVault.sol";
import "../src/VaultFactory.sol";

/// Deploy script - sets up the protocol at genesis (deploy-script peripheral)
contract DeployVault {
    function run() external {
        VaultFactory factory = new VaultFactory();
        address vault = factory.createVault(msg.sender);
        // constructor assumptions baked here
        CoreVault(vault).deposit(1e18);
    }
}
