// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// signature-replay-missing-domain detector. DO NOT DEPLOY.
contract SigReplayVuln {
    mapping(address => uint256) public balances;

    // Raw ecrecover over abi.encodePacked(to, amount) — no EIP-712 domain,
    // no chainId, no nonce, no deadline. Same signature is infinitely
    // replayable on this contract and on any identical deployment on
    // another chain.
    function withdrawWithSig(
        address to,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(to, amount));
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "bad sig");
        balances[to] -= amount;
        payable(to).transfer(amount);
    }
}
