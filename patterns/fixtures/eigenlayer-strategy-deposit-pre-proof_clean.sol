// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same deposit shape as
/// the vuln fixture, but every payable entry gates on a beacon-chain
/// proof before touching operator accounting.
interface IEigenPod {
    function stake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot)
        external
        payable;
}

contract EigenLayerStrategyClean {
    IEigenPod public eigenPod;
    bytes32 public withdrawalCredentials;

    mapping(bytes => bool) public provenValidators;
    mapping(address => uint256) public operatorShares;

    constructor(address _pod) {
        eigenPod = IEigenPod(_pod);
    }

    /// Internal proof gate. The body-regex guard in the detector accepts
    /// `_requireProven`, `verifyProof`, `verifyValidator`,
    /// `verifyWithdrawalCredentials`, `onlyAfterProof`, or `beaconProof`.
    function _requireProven(bytes calldata pubkey) internal view {
        require(provenValidators[pubkey], "validator not proven");
    }

    // Admin-gated proof acceptance path. Off-hot path for the detector:
    // it is NOT a payable deposit entry.
    function verifyWithdrawalCredentials(bytes calldata pubkey) external {
        // (omitted) verify BeaconChainProof here
        provenValidators[pubkey] = true;
    }

    // CLEAN: deposit entry gated on proof before any state mutation.
    function depositToStrategy(bytes calldata pubkey) external payable {
        require(msg.value == 32 ether, "need 32 ETH");
        _requireProven(pubkey);
        operatorShares[msg.sender] += msg.value;
        eigenPod.stake{value: msg.value}(pubkey, "", bytes32(0));
    }

    function stakeETH(bytes calldata pubkey) external payable {
        _requireProven(pubkey);
        operatorShares[msg.sender] += msg.value;
    }
}
