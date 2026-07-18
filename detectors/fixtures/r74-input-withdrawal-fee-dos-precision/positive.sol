pragma solidity ^0.8.20;

contract DustWithdrawalFeeDosPositive {
    uint256 internal constant BPS = 10_000;

    uint256 public withdrawalFeeBps = 15;
    uint256 public protocolFeeDebt;
    mapping(address => uint256) public balances;

    function deposit(uint256 assets) external {
        balances[msg.sender] += assets;
    }

    function withdraw(uint256 assets) external returns (uint256 netAssets) {
        require(balances[msg.sender] >= assets, "insufficient");

        uint256 fee = assets * withdrawalFeeBps / BPS;
        balances[msg.sender] -= assets;
        protocolFeeDebt += assets * withdrawalFeeBps / BPS;
        netAssets = assets - fee;
    }
}
