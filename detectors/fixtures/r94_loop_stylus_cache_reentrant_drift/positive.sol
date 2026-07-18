// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract R94LoopStylusCacheReentrantDriftPositive {
    mapping(bytes32 => uint256) private localCache;
    mapping(address => uint256) public storedValue;

    function seed(bytes32 key, uint256 value) external {
        localCache[key] = value;
        storedValue[msg.sender] = value;
    }

    function execute(bytes32 key, address target, bytes calldata data)
        external
        returns (bytes memory returndata)
    {
        uint256 cachedValue = localCache[key];
        (bool ok, bytes memory response) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        storedValue[msg.sender] = cachedValue;
        return response;
    }
}
