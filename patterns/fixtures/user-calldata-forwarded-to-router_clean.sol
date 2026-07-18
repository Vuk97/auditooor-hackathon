// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

// CLEAN: sellingCode must begin with an allowed selector (the router's
// own `swap` function). Selector whitelist prevents transferFrom /
// approve / permit smuggling.
contract LeverageRouterClean {
    address public owner;
    mapping(bytes4 => bool) public allowedSelector;

    constructor() {
        owner = msg.sender;
        // pre-populate with known-safe swap selectors
        allowedSelector[bytes4(0x414bf389)] = true; // exactInputSingle
        allowedSelector[bytes4(0x12aa3caf)] = true; // 1inch swap
    }

    function sell(
        uint256 loanId,
        bytes calldata sellingCode,
        address tokenHolder,
        address inchRouter,
        address integratorFeeAddress,
        address whitelistedDex
    ) external payable {
        require(sellingCode.length >= 4, "short calldata");
        bytes4 sel = bytes4(sellingCode[0:4]);
        require(allowedSelector[sel], "selector not allowed");
        (bool ok, ) = inchRouter.call(sellingCode);
        require(ok, "call failed");
    }
}
