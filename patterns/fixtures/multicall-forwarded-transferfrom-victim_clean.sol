// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MulticallClean {
    // CLEAN: self-delegate only, OZ-style
    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory ret) = address(this).delegatecall(data[i]);
            require(ok, "sub-call failed");
            results[i] = ret;
        }
    }
}
