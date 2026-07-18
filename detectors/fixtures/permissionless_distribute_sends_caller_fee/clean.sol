pragma solidity ^0.8.20;

contract PermissionlessDistributeSendsCallerFeeClean {
    mapping(uint256 => uint256) public pendingRewards;
    uint256 public royaltyFees;
    address public keeper;

    constructor(address initialKeeper) {
        keeper = initialKeeper;
    }

    modifier onlyKeeper() {
        require(msg.sender == keeper, "keeper");
        _;
    }

    receive() external payable {}

    function depositRewards(uint256 credId) external payable {
        pendingRewards[credId] += msg.value;
        royaltyFees += msg.value / 10;
    }

    function distribute(uint256 credId) external onlyKeeper {
        uint256 reward = pendingRewards[credId];
        uint256 royaltyFee = reward / 20;

        pendingRewards[credId] = 0;
        royaltyFees -= royaltyFee;
        payable(keeper).transfer(royaltyFee);
    }
}
