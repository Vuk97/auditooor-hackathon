pragma solidity ^0.8.20;

contract PerpBridgeOutFeeDonationConsumesRecipientBalanceClean {
    mapping(address => uint256) public multichainBalance;

    function executeDeposit(address account, address receiver, uint256 marketTokens) external {
        if (account != receiver) {
            return;
        }
        multichainBalance[receiver] += 1 ether;
        mintMarketTokens(receiver, marketTokens);
        bridgeOut(receiver, marketTokens, account);
    }

    function mintMarketTokens(address receiver, uint256 marketTokens) internal pure {
        receiver;
        marketTokens;
    }

    function bridgeOut(address tokenReceiver, uint256 amount, address feePayerAccount) internal pure {
        tokenReceiver;
        amount;
        feePayerAccount;
    }
}
