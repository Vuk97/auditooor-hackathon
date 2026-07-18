// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICallback { function onFulfill(uint256 id, bytes calldata data) external; }

contract CeiViolationFulfillBeforeStorageVuln {
    mapping(uint256 => bool) public fulfilledRequests;
    mapping(uint256 => address) public callbacks;

    function request(uint256 id, address cb) external {
        callbacks[id] = cb;
    }

    function fulfill(uint256 id, bytes calldata data) external {
        require(!fulfilledRequests[id], "already");
        // VULN: callback before the storage write — enables cross-function re-entry.
        ICallback(callbacks[id]).onFulfill(id, data);
        fulfilledRequests[id] = true;
    }
}
