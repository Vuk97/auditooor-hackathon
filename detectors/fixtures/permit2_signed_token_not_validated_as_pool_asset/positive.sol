// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPermit2Positive {
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

contract Permit2SignedTokenNotValidatedAsPoolAssetPositive {
    IPermit2Positive public immutable permit2;
    address private immutable poolAsset;
    mapping(address => uint256) public shares;

    constructor(IPermit2Positive permit2_, address poolAsset_) {
        permit2 = permit2_;
        poolAsset = poolAsset_;
    }

    function asset() public view returns (address) {
        return poolAsset;
    }

    function depositWithPermit(
        uint256 assets,
        IPermit2Positive.PermitTransferFrom calldata permit,
        bytes calldata signature
    ) external {
        IPermit2Positive.SignatureTransferDetails memory details = IPermit2Positive.SignatureTransferDetails({
            to: address(this),
            requestedAmount: assets
        });

        permit2.permitTransferFrom(permit, details, msg.sender, signature);
        shares[msg.sender] += assets;
    }
}
