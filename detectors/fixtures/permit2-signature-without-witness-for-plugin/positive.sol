pragma solidity ^0.8.20;

interface IAllowanceTransfer {
    struct PermitSingle {
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    struct AllowanceTransferDetails {
        address from;
        address to;
        uint160 amount;
        address token;
    }

    function permit(address owner, PermitSingle calldata permitSingle, bytes calldata signature) external;
    function transferFrom(AllowanceTransferDetails calldata details) external;
}

contract Permit2ProxyWithPlugin {
    IAllowanceTransfer public immutable permit2;

    constructor(IAllowanceTransfer permit2_) {
        permit2 = permit2_;
    }

    function executeWithPermit(
        address plugin,
        bytes calldata pluginData,
        address owner,
        IAllowanceTransfer.PermitSingle calldata permitSingle,
        IAllowanceTransfer.AllowanceTransferDetails calldata details,
        bytes calldata signature
    ) external {
        permit2.permit(owner, permitSingle, signature);
        permit2.transferFrom(details);

        (bool ok, ) = plugin.delegatecall(pluginData);
        require(ok, "plugin delegatecall failed");
    }
}
