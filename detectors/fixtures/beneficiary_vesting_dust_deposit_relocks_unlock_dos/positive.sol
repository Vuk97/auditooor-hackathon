pragma solidity ^0.8.20;

interface IERC20Minimal {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VestingDustDepositRelockDosPositive {
    IERC20Minimal public immutable token;
    uint256 public vestingTerm = 30 days;
    mapping(address => uint256) public releaseTime;
    mapping(address => uint256) public vestedAmount;

    constructor(IERC20Minimal _token) {
        token = _token;
    }

    function depositFor(address beneficiary, uint256 amount) external {
        require(beneficiary != address(0), "zero beneficiary");
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
        vestedAmount[beneficiary] += amount;
        releaseTime[beneficiary] = block.timestamp + vestingTerm;
    }

    function claimable(address beneficiary) external view returns (bool) {
        return block.timestamp >= releaseTime[beneficiary] && vestedAmount[beneficiary] > 0;
    }
}
