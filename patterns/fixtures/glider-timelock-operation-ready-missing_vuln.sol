// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract TimelockVuln {
    mapping(bytes32 => uint256) public _timestamps;

    function isOperationReady(bytes32 id) public view returns (bool) {
        return _timestamps[id] != 0 && _timestamps[id] <= block.timestamp;
    }

    // VULN: missing isOperationReady in _beforeCall
    function _beforeCall(bytes32 id, bytes32 predecessor) internal view {
        if (predecessor != bytes32(0)) {
            require(_timestamps[predecessor] != 0, "missing predecessor");
        }
        id;
    }

    function execute(bytes32 id, bytes32 predecessor) external {
        _beforeCall(id, predecessor);
    }
}
