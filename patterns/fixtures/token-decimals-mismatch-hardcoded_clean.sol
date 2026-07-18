// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function decimals() external view returns (uint8);
}

contract TokenDecimalsMismatchHardcodedClean {
    IERC20 public token;
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // CLEAN: reads token.decimals() and normalises dynamically. The presence
    // of `.decimals()` in the body suppresses the detector.
    function _handleDeposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        uint256 tokenDecimals = uint256(token.decimals());
        uint256 credited = amount * (10 ** (18 - tokenDecimals));
        shares[msg.sender] += credited;
        totalShares += credited;
    }

    // CLEAN: withdraw path also reads decimals() to normalise.
    function _handleWithdraw(uint256 shareAmount) external {
        require(shares[msg.sender] >= shareAmount, "insufficient");
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        uint256 tokenDecimals = uint256(token.decimals());
        uint256 tokensOut = shareAmount / (10 ** (18 - tokenDecimals));
        token.transfer(msg.sender, tokensOut);
    }

    // CLEAN: pricing helper that routes through a normalizeDecimals helper
    // (name-matched by the suppressor regex).
    function priceOf(uint256 amount) external view returns (uint256) {
        uint256 tokenDecimals = uint256(token.decimals());
        return amount * (10 ** tokenDecimals);
    }
}
