// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

library SafeERC20 {
    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        (bool success, bytes memory data) = address(token).call(
            abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, amount)
        );
        require(success, "erc20 transfer failed");
        if (data.length > 0) {
            require(abi.decode(data, (bool)), "erc20 transfer returned false");
        }
    }
}

contract DepositNoncompliantErc20Clean {
    using SafeERC20 for IERC20;

    mapping(address => uint256) public deposited;
    uint256 public totalDeposited;

    function depositWithERC20(address token, uint256 amount) external {
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        deposited[msg.sender] += amount;
        totalDeposited += amount;
    }
}
