// SPDX-License-Identifier: MIT
// Fixture: weth-unwrap-to-non-receiving-contract — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

interface IWETH9 {
    function withdraw(uint256) external;
    function deposit() external payable;
    function transferFrom(address, address, uint256) external returns (bool);
}

contract VulnWETHUnwrapper {
    IWETH9 public constant WETH = IWETH9(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    mapping(address => uint256) public wethBalance;

    // VULN: function unwraps WETH via WETH.withdraw, then forwards native
    // ETH to msg.sender. No try/catch, no code-length guard, no
    // receiveETH fallback. Any contract caller without a payable
    // receive()/fallback (or one consuming more than the 2300-gas
    // stipend for .transfer) will cause the entire interaction to
    // revert, permanently locking contract wallets (Safes, routers) out
    // of the withdraw path.
    function withdrawAsETH(uint256 amount) external {
        require(wethBalance[msg.sender] >= amount, "insufficient");
        wethBalance[msg.sender] -= amount;

        // Unwrap WETH -> native ETH in this contract's balance.
        WETH.withdraw(amount);

        // Forward raw ETH back to sender assuming EOA semantics.
        payable(msg.sender).transfer(amount);
    }

    // Needed so WETH.withdraw can push ETH into this contract.
    receive() external payable {}
}
