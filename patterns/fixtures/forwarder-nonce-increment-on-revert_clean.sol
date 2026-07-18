// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// CLEAN: forwarder reverts on inner-call failure so nonce is only consumed on success.
contract MinimalForwarderClean {
    mapping(address => uint256) public nonces;

    struct ForwardRequest { address from; address to; uint256 value; uint256 gas; uint256 nonce; bytes data; }

    function execute(ForwardRequest calldata req) external payable returns (bool, bytes memory) {
        require(nonces[req.from] == req.nonce, "bad nonce");
        nonces[req.from]++;
        (bool success, bytes memory ret) = req.to.call{value: req.value, gas: req.gas}(req.data);
        require(success, "inner call failed");
        return (success, ret);
    }
}
