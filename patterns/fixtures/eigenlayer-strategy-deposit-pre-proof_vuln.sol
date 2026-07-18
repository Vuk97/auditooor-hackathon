// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// eigenlayer-strategy-deposit-pre-proof detector. DO NOT DEPLOY.
///
/// This strategy accepts native ETH stake and mints operator shares
/// before any beacon-chain proof has bound the deposit to a specific
/// validator. An attacker can front-run the later proof transaction
/// with their own proof and redirect future rewards.
interface IEigenPod {
    function stake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot)
        external
        payable;
}

contract EigenLayerStrategyVuln {
    // References that satisfy the contract-level precondition
    // (EigenPod|beaconChain|BLSPubkey|withdrawalCredentials).
    IEigenPod public eigenPod;
    bytes32 public withdrawalCredentials;

    mapping(address => uint256) public operatorShares;

    constructor(address _pod) {
        eigenPod = IEigenPod(_pod);
    }

    // VULN: payable deposit that mints shares immediately; no verifyProof /
    // verifyValidator / verifyWithdrawalCredentials / _requireProven
    // reference anywhere in the body.
    function depositToStrategy(bytes calldata pubkey) external payable {
        require(msg.value == 32 ether, "need 32 ETH");
        // Mint operator shares against the deposit before any proof is
        // asserted. A front-runner can bind pubkey to their own validator.
        operatorShares[msg.sender] += msg.value;
        eigenPod.stake{value: msg.value}(pubkey, "", bytes32(0));
    }

    function stakeETH() external payable {
        // Second entry surface, same shape, same problem.
        operatorShares[msg.sender] += msg.value;
    }
}
