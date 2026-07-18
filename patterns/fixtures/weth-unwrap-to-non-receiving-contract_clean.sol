// SPDX-License-Identifier: MIT
// Fixture: weth-unwrap-to-non-receiving-contract — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

interface IWETH9 {
    function withdraw(uint256) external;
    function deposit() external payable;
    function transfer(address, uint256) external returns (bool);
}

contract CleanWETHUnwrapper {
    IWETH9 public constant WETH = IWETH9(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    mapping(address => uint256) public wethBalance;

    // CLEAN fix #1: detect contract recipients via code.length and route
    // them through a WETH-denominated path. Only EOAs receive raw ETH.
    function withdrawAsETH(uint256 amount) external {
        require(wethBalance[msg.sender] >= amount, "insufficient");
        wethBalance[msg.sender] -= amount;

        if (msg.sender.code.length > 0) {
            // Contract caller — keep it as WETH.
            WETH.transfer(msg.sender, amount);
        } else {
            // EOA caller — safe to unwrap and push ETH.
            WETH.withdraw(amount);
            (bool ok, ) = payable(msg.sender).call{value: amount}("");
            require(ok, "eth send failed");
        }
    }

    // CLEAN fix #2: wrap the unwrap-and-forward in a try/catch that
    // re-wraps on failure, so contract callers without a payable
    // receive() still get their funds as WETH rather than a revert.
    function withdrawAsETHWithFallback(uint256 amount) external {
        require(wethBalance[msg.sender] >= amount, "insufficient");
        wethBalance[msg.sender] -= amount;

        WETH.withdraw(amount);
        try this.forwardETH(msg.sender, amount) {
            // delivered as ETH
        } catch {
            // re-wrap and deliver as WETH
            IWETH9(address(WETH)).deposit{value: amount}();
            WETH.transfer(msg.sender, amount);
        }
    }

    function forwardETH(address to, uint256 amount) external {
        require(msg.sender == address(this), "self only");
        (bool ok, ) = payable(to).call{value: amount}("");
        require(ok, "eth send failed");
    }

    receive() external payable {}
}
