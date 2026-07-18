// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RouterAdapterArbitraryTargetCallClean {
    mapping(address => bool) public approvedTargets;

    function setApprovedTarget(address t, bool ok) external {
        approvedTargets[t] = ok;
    }

    function swap(address target, bytes calldata data) external returns (bytes memory) {
        require(approvedTargets[target], "target not approved");
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "call failed");
        return ret;
    }
}
