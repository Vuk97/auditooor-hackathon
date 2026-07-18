// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same cross-chain send
/// shape as the vuln fixture, but the forwarded gas limit is padded by
/// destination-chain intrinsic + per-byte + chain-specific overhead before
/// it is handed to the canonical messenger. An under-estimate on the
/// caller side cannot produce an out-of-gas delivery revert.

interface IL1Messenger {
    function sendMessage(address target, bytes calldata data, uint256 gasLimit) external;
}

contract GasEstimationCrossChainClean {
    IL1Messenger public messenger;

    uint256 public constant INTRINSIC_GAS = 21000;
    uint256 internal constant _minGasPerByte = 16;

    // Per-destination rollup-specific overhead (Arbitrum L1-cost, Optimism
    // rollup fee, zkSync proof overhead). Populated by the protocol owner
    // per supported chain.
    mapping(uint256 => uint256) public OVERHEAD_GAS;

    constructor(address _messenger) {
        messenger = IL1Messenger(_messenger);
    }

    function sendToL2(
        address target,
        bytes calldata data,
        uint256 _gasLimit,
        uint256 destChainId
    ) external {
        uint256 padded =
            _gasLimit +
            INTRINSIC_GAS +
            data.length * _minGasPerByte +
            OVERHEAD_GAS[destChainId];

        messenger.sendMessage(target, data, padded);
    }

    function _sendMessage(
        address target,
        bytes calldata data,
        uint256 gasLimit,
        uint256 destChainId
    ) external {
        uint256 padded =
            gasLimit +
            INTRINSIC_GAS +
            data.length * _minGasPerByte +
            OVERHEAD_GAS[destChainId];

        messenger.sendMessage(target, data, padded);
    }
}
