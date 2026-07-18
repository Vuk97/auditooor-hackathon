// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// VULN: EIP-2771 forwarder burns nonce even if the inner call reverts.
contract MinimalForwarderVuln {
    mapping(address => uint256) public nonces;

    struct ForwardRequest { address from; address to; uint256 value; uint256 gas; uint256 nonce; bytes data; }

    function execute(ForwardRequest calldata req) external payable returns (bool, bytes memory) {
        require(nonces[req.from] == req.nonce, "bad nonce");
        nonces[req.from]++;  // bumped BEFORE call
        // VULN: success discarded; failed inner call still burns nonce
        (bool success, bytes memory ret) = req.to.call{value: req.value, gas: req.gas}(req.data);
        return (success, ret);
    }
}
