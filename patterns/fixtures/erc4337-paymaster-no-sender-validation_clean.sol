// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

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

// CLEAN: the paymaster gates sponsorship on an allowlist of approved
// senders. Any UserOp whose `sender` is not present is rejected before
// the EntryPoint can debit the deposit.
contract Erc4337PaymasterSenderGatedClean {
    address public immutable entryPoint;
    mapping(address => bool) public isWhitelisted;
    bytes32 internal constant SIG_VALIDATION_SUCCESS = bytes32(0);
    bytes32 internal constant SIG_VALIDATION_FAILED = bytes32(uint256(1));

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "only EntryPoint");
        _;
    }

    function setWhitelisted(address account, bool ok) external {
        isWhitelisted[account] = ok;
    }

    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external onlyEntryPoint returns (bytes memory context, uint256 validationData) {
        (userOpHash, maxCost);
        // Bind sponsorship to the caller. isWhitelisted is the anchor
        // the detector's body_not_contains_regex looks for.
        require(isWhitelisted[userOp.sender], "sender not sponsored");
        return ("", uint256(SIG_VALIDATION_SUCCESS));
    }

    function deposit() external payable {}
}
