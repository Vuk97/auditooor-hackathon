// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like031Clean {
    function safeTransferFrom(address from, address to, uint256 amount) external;
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IRouterLike031Clean {
    function pairTransferERC20From(
        IERC20Like031Clean token,
        address from,
        address to,
        uint256 amount
    ) external;
}

interface IFactoryLike031Clean {
    function routerStatus(address router) external view returns (bool);
}

contract RoyaltyProtocolPairMeasured031 {
    IERC20Like031Clean public immutable token;
    IFactoryLike031Clean public immutable factory;
    address public immutable protocolFeeRecipient;
    address public immutable royaltyRecipient;

    constructor(
        IERC20Like031Clean token_,
        IFactoryLike031Clean factory_,
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
        uint256 balanceBefore = token.balanceOf(address(this));

        if (factory.routerStatus(msg.sender)) {
            IRouterLike031Clean(msg.sender).pairTransferERC20From(token, payer, address(this), expected);
        } else {
            token.safeTransferFrom(payer, address(this), expected);
        }

        uint256 balanceAfter = token.balanceOf(address(this));
        uint256 actualReceived = balanceAfter - balanceBefore;
        require(actualReceived >= expected, "router skipped fee");

        token.transfer(protocolFeeRecipient, protocolFee);
        token.transfer(royaltyRecipient, royaltyAmount);
    }
}
