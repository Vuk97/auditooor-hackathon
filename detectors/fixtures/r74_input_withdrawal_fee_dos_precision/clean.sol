pragma solidity ^0.8.20;

contract DustWithdrawalFeeDosClean {
    uint256 internal constant BPS = 10_000;

    uint256 public withdrawalFeeBps = 15;
    uint256 public protocolFeeDebt;
    mapping(address => uint256) public balances;

    function deposit(uint256 assets) external {
        balances[msg.sender] += assets;
    }

    function withdraw(uint256 assets) external returns (uint256 netAssets) {
        require(balances[msg.sender] >= assets, "insufficient");

        uint256 fee = ceilDiv(assets * withdrawalFeeBps, BPS);
        balances[msg.sender] -= assets;
        protocolFeeDebt += fee;
        netAssets = assets - fee;
    }

    function ceilDiv(uint256 x, uint256 y) internal pure returns (uint256) {
        if (x == 0) {
            return 0;
        }
        return ((x - 1) / y) + 1;
    }
}
