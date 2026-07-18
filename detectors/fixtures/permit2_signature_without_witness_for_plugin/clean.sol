pragma solidity ^0.8.20;

interface ISignatureTransfer {
    struct PermitTransferFrom {
        address token;
        uint256 amount;
        uint256 nonce;
        uint256 deadline;
    }

    struct SignatureTransferDetails {
        address to;
        uint256 requestedAmount;
    }

    function permitWitnessTransferFrom(
        PermitTransferFrom calldata permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes32 witness,
        string calldata witnessTypeString,
        bytes calldata signature
    ) external;
}

contract Permit2ProxyWithWitnessBoundPlugin {
    ISignatureTransfer public immutable permit2;

    constructor(ISignatureTransfer permit2_) {
        permit2 = permit2_;
    }

    function executeWithPermit(
        address plugin,
        bytes calldata pluginData,
        address owner,
        ISignatureTransfer.PermitTransferFrom calldata permitTransfer,
        ISignatureTransfer.SignatureTransferDetails calldata details,
        bytes32 witness,
        bytes calldata signature
    ) external {
        permit2.permitWitnessTransferFrom(
            permitTransfer,
            details,
            owner,
            witness,
            "Intent(address plugin,bytes pluginData)",
            signature
        );

        (bool ok, ) = plugin.delegatecall(pluginData);
        require(ok, "plugin delegatecall failed");
    }
}
