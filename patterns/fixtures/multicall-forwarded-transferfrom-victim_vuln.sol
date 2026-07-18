// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MulticallVuln {
    struct Call { address target; bytes callData; uint256 value; bool allowFailure; }

    // VULN: arbitrary target with value, contract holds third-party approvals
    function multicall(Call[] calldata calls) external payable returns (bytes[] memory results) {
        results = new bytes[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, bytes memory ret) = calls[i].target.call{value: calls[i].value}(calls[i].callData);
            require(ok || calls[i].allowFailure, "sub-call failed");
            results[i] = ret;
        }
    }
}
