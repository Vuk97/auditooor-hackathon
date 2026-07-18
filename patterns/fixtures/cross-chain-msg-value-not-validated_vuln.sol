// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Mintable {
    function mint(address to, uint256 amount) external;
}

contract XChainHandlerVuln {
    IERC20Mintable public immutable token;
    address public immutable trustedRouter;

    constructor(address _t, address _r) { token = IERC20Mintable(_t); trustedRouter = _r; }

    // Detector MUST fire: amount is read from payload and minted with no validation.
    function handleMessage(bytes calldata payload) external {
        require(msg.sender == trustedRouter, "only router");
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        token.mint(to, amount);
    }
}
