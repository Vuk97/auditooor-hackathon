// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// gas-estimation-cross-chain-undercount detector. DO NOT DEPLOY.
///
/// `sendToL2` forwards a caller-supplied `_gasLimit` directly to the
/// canonical messenger without adding destination-chain intrinsic /
/// overhead padding. A value estimated on L1 will undercount the L2
/// intrinsic cost — delivery reverts OOG and the message is stuck.

interface IL1Messenger {
    function sendMessage(address target, bytes calldata data, uint256 gasLimit) external;
}

contract GasEstimationCrossChainVuln {
    IL1Messenger public messenger;

    constructor(address _messenger) {
        messenger = IL1Messenger(_messenger);
    }

    /// @dev Entry point: `sendMessage` string is present so the contract-
    /// level `has_function_body_matching` precondition passes.
    function sendToL2(
        address target,
        bytes calldata data,
        uint256 _gasLimit
    ) external {
        // VULN: caller-supplied gas is forwarded with no padding for the
        // destination-chain intrinsic cost — undercount risk on L2.
        messenger.sendMessage(target, data, _gasLimit);
    }

    /// @dev Secondary cross-chain surface to satisfy the name_matches regex
    /// on its own body.
    function _sendMessage(
        address target,
        bytes calldata data,
        uint256 gasLimit
    ) external {
        messenger.sendMessage(target, data, gasLimit);
    }
}
