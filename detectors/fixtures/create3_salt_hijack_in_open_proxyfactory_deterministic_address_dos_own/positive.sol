// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library CREATE3 {
    event Deployed(address deployed, bytes32 salt);

    function deploy(bytes32 salt, bytes memory creationCode, uint256 value) internal returns (address deployed) {
        require(creationCode.length != 0, "empty creation code");
        deployed = address(uint160(uint256(keccak256(abi.encodePacked(salt, creationCode, value)))));
        emit Deployed(deployed, salt);
    }
}

contract OpenProxyFactory {
    event ProxyCreated(address proxy, bytes32 salt, address owner);

    function createProxy(bytes32 salt, bytes calldata initializer) external payable returns (address proxy) {
        bytes memory bytecode = abi.encodePacked(type(ManagedProxy).creationCode, initializer);
        proxy = CREATE3.deploy(salt, bytecode, msg.value);
        ManagedProxy(payable(proxy)).initialize(msg.sender);
        emit ProxyCreated(proxy, salt, msg.sender);
    }
}

contract ManagedProxy {
    address public owner;

    function initialize(address newOwner) external {
        require(owner == address(0), "initialized");
        owner = newOwner;
    }
}
