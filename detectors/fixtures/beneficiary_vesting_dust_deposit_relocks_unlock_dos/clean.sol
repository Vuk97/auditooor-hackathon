pragma solidity ^0.8.20;

interface IERC20MinimalClean {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VestingDustDepositRelockDosClean {
    IERC20MinimalClean public immutable token;
    uint256 public constant MIN_VESTING_DEPOSIT = 1 ether;
    uint256 public vestingTerm = 30 days;
    mapping(address => uint256) public releaseTime;
    mapping(address => uint256) public vestedAmount;

    constructor(IERC20MinimalClean _token) {
        token = _token;
    }

    function depositFor(address beneficiary, uint256 amount) external {
        require(beneficiary == msg.sender, "self only");
        require(amount >= MIN_VESTING_DEPOSIT, "dust");
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
        vestedAmount[beneficiary] += amount;
        if (releaseTime[beneficiary] < block.timestamp) {
            releaseTime[beneficiary] = block.timestamp + vestingTerm;
        }
    }

    function claimable(address beneficiary) external view returns (bool) {
        return block.timestamp >= releaseTime[beneficiary] && vestedAmount[beneficiary] > 0;
    }
}
