// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function safeTransfer(address to, uint256 amount) external;
}

interface IATokenLike {
    function rescueTokens(address token, address to, uint256 amount) external;
}

contract WeakPool {
    function rescueTokensFromAToken(
        IATokenLike aToken,
        address token,
        address to,
        uint256 amount
    ) external {
        aToken.rescueTokens(token, to, amount);
    }
}

contract ATokenLike {
    address public immutable POOL;

    constructor(address pool) {
        POOL = pool;
    }

    modifier onlyPool() {
        require(msg.sender == POOL, "ONLY_POOL");
        _;
    }

    function rescueTokens(address token, address to, uint256 amount) external onlyPool {
        IERC20Like(token).safeTransfer(to, amount);
    }
}
