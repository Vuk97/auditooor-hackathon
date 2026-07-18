pragma solidity ^0.8.20;

contract CollateralExitModifierVulnerable {
    mapping(address => uint256) public collateral;
    mapping(address => bool) public exitRequested;
    mapping(address => uint256) public exitAvailableAt;
    address public admin;
    bool public paused;
    uint256 public totalCollateral;

    constructor() {
        admin = msg.sender;
    }

    receive() external payable {}

    modifier onlyCooldownComplete(address account) {
        require(exitRequested[account], "request exit");
        require(block.timestamp >= exitAvailableAt[account], "exit delay");
        _;
    }

    function deposit() external payable {
        require(msg.value > 0, "value");
        collateral[msg.sender] += msg.value;
        totalCollateral += msg.value;
    }

    function requestExit() external {
        require(collateral[msg.sender] > 0, "collateral");
        exitRequested[msg.sender] = true;
        exitAvailableAt[msg.sender] = block.timestamp + 3 days;
    }

    function withdrawAfterExit(uint256 amount) external onlyCooldownComplete(msg.sender) {
        _releaseCollateral(msg.sender, amount);
    }

    function emergencyRelease(uint256 amount) external {
        _releaseCollateral(msg.sender, amount);
    }

    function _releaseCollateral(address account, uint256 amount) internal {
        require(collateral[account] >= amount, "amount");
        collateral[account] -= amount;
        totalCollateral -= amount;
        payable(account).transfer(amount);
    }
}
