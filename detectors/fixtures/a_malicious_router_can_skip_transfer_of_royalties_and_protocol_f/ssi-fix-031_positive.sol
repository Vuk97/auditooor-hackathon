// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like031 {
    function safeTransferFrom(address from, address to, uint256 amount) external;
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IRouterLike031 {
    function pairTransferERC20From(
        IERC20Like031 token,
        address from,
        address to,
        uint256 amount
    ) external;
}

interface IFactoryLike031 {
    function routerStatus(address router) external view returns (bool);
}

contract RoyaltyProtocolPairVulnerable031 {
    IERC20Like031 public immutable token;
    IFactoryLike031 public immutable factory;
    address public immutable protocolFeeRecipient;
    address public immutable royaltyRecipient;

    constructor(
        IERC20Like031 token_,
        IFactoryLike031 factory_,
        address protocolFeeRecipient_,
        address royaltyRecipient_
    ) {
        token = token_;
        factory = factory_;
        protocolFeeRecipient = protocolFeeRecipient_;
        royaltyRecipient = royaltyRecipient_;
    }

    function buyWithToken(
        address payer,
        uint256 saleAmount,
        uint256 protocolFee,
        uint256 royaltyAmount
    ) external {
        _pullTokenInputAndPayProtocolFee(payer, saleAmount, protocolFee, royaltyAmount);
    }

    function _pullTokenInputAndPayProtocolFee(
        address payer,
        uint256 saleAmount,
        uint256 protocolFee,
        uint256 royaltyAmount
    ) internal {
        uint256 expected = saleAmount + protocolFee + royaltyAmount;
        if (factory.routerStatus(msg.sender)) {
            IRouterLike031(msg.sender).pairTransferERC20From(token, payer, address(this), expected);
        } else {
            token.safeTransferFrom(payer, address(this), expected);
        }

        token.transfer(protocolFeeRecipient, protocolFee);
        token.transfer(royaltyRecipient, royaltyAmount);
    }
}
