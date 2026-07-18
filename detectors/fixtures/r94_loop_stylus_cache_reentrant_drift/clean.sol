// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract R94LoopStylusCacheReentrantDriftClean {
    mapping(bytes32 => uint256) private snapshotValue;
    mapping(address => uint256) public storedValue;

    function execute(address target, bytes calldata data) external returns (bytes memory response) {
        uint256 cachedValue = snapshotValue[keccak256(data)];
        (bool ok, bytes memory returndata) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        storedValue[msg.sender] = cachedValue;
        return returndata;
    }
}
