// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Mintable {
    function mint(address to, uint256 amount) external;
}

contract XChainHandlerClean {
    IERC20Mintable public immutable token;
    address public immutable trustedRouter;
    uint256 public dailyCap;
    uint256 public spentToday;

    constructor(address _t, address _r, uint256 _cap) {
        token = IERC20Mintable(_t); trustedRouter = _r; dailyCap = _cap;
    }

    // Detector MUST NOT fire: amount validated against cap and > 0 before mint.
    function handleMessage(bytes calldata payload) external {
        require(msg.sender == trustedRouter, "only router");
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        require(amount > 0 && amount <= dailyCap, "bad amount");
        require(spentToday + amount <= dailyCap, "cap exceeded");
        spentToday += amount;
        token.mint(to, amount);
    }
}
