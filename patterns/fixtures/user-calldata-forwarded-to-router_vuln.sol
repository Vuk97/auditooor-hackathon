// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

// VULN: LeverageUp-style margin router. `sellingCode` is user-controlled
// bytes forwarded via low-level call into the whitelisted inchRouter.
// Because users have approved inchRouter for arbitrary amounts, the
// payload can encode transferFrom(victim, attacker, amount).
contract LeverageRouterVuln {
    address public owner;
    mapping(address => bool) public whitelistedDex;

    constructor() { owner = msg.sender; }

    function sell(
        uint256 loanId,
        bytes calldata sellingCode,
        address tokenHolder,
        address inchRouter,
        address integratorFeeAddress,
        address whitelistedDexAddr
    ) external payable {
        // No selector check, no target allowlist — attacker encodes
        // anything in sellingCode and the router executes it.
        (bool ok, ) = inchRouter.call(sellingCode);
        require(ok, "call failed");
    }
}
