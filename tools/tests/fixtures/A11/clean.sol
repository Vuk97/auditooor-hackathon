// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// A delegatecall-TARGET logic module. Its context-sensitive entrypoint
// `setConfig` writes storage and is protected by an onlyProxy context-binding
// guard (address(this) != __self). BENIGN: the guard binds the context.
contract LogicModule {
    address public immutable __self;
    uint256 public config;

    constructor() {
        __self = address(this);
    }

    // context-binding guard: reverts on a direct (non-delegatecall) call.
    modifier onlyProxy() {
        require(address(this) != __self, "only delegatecall");
        _;
    }

    // guarded context-sensitive write -> must NOT be flagged.
    function setConfig(uint256 v) external onlyProxy {
        config = v;
    }
}
