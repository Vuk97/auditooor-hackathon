pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract R94LoopTradeMissingProgramSignerSolPositive {
    IERC20 public immutable asset;

    constructor(IERC20 asset_) {
        asset = asset_;
    }

    function executeTrade(address recipient, uint256 amount) external {
        require(recipient != address(0), "recipient");
        asset.transfer(recipient, amount);
    }
}
