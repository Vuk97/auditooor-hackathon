pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract R94LoopTradeMissingProgramSignerSolClean {
    IERC20 public immutable asset;
    address public immutable expectedRouter;

    constructor(IERC20 asset_, address expectedRouter_) {
        asset = asset_;
        expectedRouter = expectedRouter_;
    }

    function executeTrade(address recipient, uint256 amount) external {
        require(msg.sender == expectedRouter, "only router");
        require(recipient != address(0), "recipient");
        asset.transfer(recipient, amount);
    }
}
