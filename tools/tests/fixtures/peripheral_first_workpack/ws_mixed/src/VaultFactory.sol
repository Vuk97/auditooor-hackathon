// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./CoreVault.sol";

/// @title VaultFactory - deploys new vault instances (factory peripheral)
contract VaultFactory {
    address[] public vaults;

    function createVault(address owner) external returns (address vault) {
        CoreVault v = new CoreVault();
        vaults.push(address(v));
        vault = address(v);
    }

    function cloneVault(address template) external returns (address) {
        // minimal proxy clone
        return _clone(template);
    }

    function _clone(address template) internal returns (address result) {
        // EIP-1167 bytecode clone
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), shl(0x60, template))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            result := create(0, ptr, 0x37)
        }
    }
}
