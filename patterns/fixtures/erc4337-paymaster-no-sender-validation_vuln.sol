// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal ERC-4337 types — kept local to keep the fixture self-contained.
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

// VULN: the paymaster's validatePaymasterUserOp returns success for any
// UserOp regardless of who userOp.sender is. Anyone who can submit a
// UserOperation through a bundler will have this paymaster pay their
// gas. The deposit drains at bundler RPS until empty.
contract Erc4337PaymasterNoSenderValidationVuln {
    address public immutable entryPoint;
    bytes32 internal constant SIG_VALIDATION_SUCCESS = bytes32(0);

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "only EntryPoint");
        _;
    }

    // Called by the EntryPoint during validation. No check on
    // userOp.sender, no allowlist, no intent, no operator signature
    // binding the caller — unconditional sponsorship.
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external onlyEntryPoint returns (bytes memory context, uint256 validationData) {
        // unused to silence warnings; the bug is the absence of a check.
        (userOp, userOpHash, maxCost);
        return ("", uint256(SIG_VALIDATION_SUCCESS));
    }

    // Owner can top up the EntryPoint deposit. Pure faucet.
    function deposit() external payable {}
}
