// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFlashBorrower {
    function onFlashLoan(address initiator, address token, uint256 amount, uint256 fee, bytes calldata data)
        external returns (bytes32);
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract FlashClean {
    IERC20 public token;
    bytes32 internal constant _RETURN_VALUE = keccak256("ERC3156FlashBorrower.onFlashLoan");

    // Clean: captures and asserts the magic return value.
    function flashLoan(IFlashBorrower receiver, uint256 amount, bytes calldata data) external {
        token.transfer(address(receiver), amount);
        bytes32 ret = receiver.onFlashLoan(msg.sender, address(token), amount, 0, data);
        require(ret == _RETURN_VALUE, "bad return");
        token.transferFrom(address(receiver), address(this), amount);
    }
}
