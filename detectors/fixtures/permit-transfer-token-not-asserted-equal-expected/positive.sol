pragma solidity ^0.8.20;

interface ISignatureTransfer {
    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    struct PermitTransferFrom {
        TokenPermissions permitted;
        uint256 nonce;
        uint256 deadline;
    }

    struct SignatureTransferDetails {
        address to;
        uint256 requestedAmount;
    }

    function permitTransferFrom(
        PermitTransferFrom calldata permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes calldata signature
    ) external;
}

contract PermitRepayWithoutTokenAssertion {
    ISignatureTransfer public immutable permit2;
    address public immutable asset;
    mapping(address => uint256) public debt;

    constructor(ISignatureTransfer permit2_, address asset_) {
        permit2 = permit2_;
        asset = asset_;
    }

    function repayWithPermit(
        bytes calldata permitData,
        uint256 expectedAmount,
        address owner,
        bytes calldata signature
    ) external {
        (
            ISignatureTransfer.PermitTransferFrom memory permit,
            ISignatureTransfer.SignatureTransferDetails memory details
        ) = abi.decode(
            permitData,
            (
                ISignatureTransfer.PermitTransferFrom,
                ISignatureTransfer.SignatureTransferDetails
            )
        );

        permit2.permitTransferFrom(permit, details, owner, signature);
        require(expectedAmount == details.requestedAmount, "amount mismatch");

        _creditRepayment(owner, expectedAmount, asset);
    }

    function _creditRepayment(address owner, uint256 amount, address repayToken) internal {
        repayToken;
        debt[owner] -= amount;
    }
}
