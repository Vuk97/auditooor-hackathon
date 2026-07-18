// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: vulnerable version of SafeTransferLib — no code-length check before calling token.
// Source: morpho-org/morpho-blue@a4cb34b (cantina audit fix)
// Vulnerability: if token address has no code (EOA or deleted contract), the low-level call
// returns success=true and empty returndata, so the require checks pass silently.
// Attacker can create markets with a non-existent token address and supply/withdraw "funds"
// that don't actually move, enabling theft of real tokens already in the pool.

contract Fix {
    string internal constant TRANSFER_REVERTED = "transfer reverted";
    string internal constant TRANSFER_RETURNED_FALSE = "transfer returned false";
    string internal constant TRANSFER_FROM_REVERTED = "transferFrom reverted";
    string internal constant TRANSFER_FROM_RETURNED_FALSE = "transferFrom returned false";

    // VULNERABLE: no code.length check — succeeds silently on EOA/dead addresses
    function safeTransfer(address token, address to, uint256 value) external {
        (bool success, bytes memory returndata) =
            token.call(abi.encodeWithSignature("transfer(address,uint256)", to, value));
        require(success, TRANSFER_REVERTED);
        require(returndata.length == 0 || abi.decode(returndata, (bool)), TRANSFER_RETURNED_FALSE);
    }

    // VULNERABLE: same issue for transferFrom
    function safeTransferFrom(address token, address from, address to, uint256 value) external {
        (bool success, bytes memory returndata) =
            token.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", from, to, value));
        require(success, TRANSFER_FROM_REVERTED);
        require(returndata.length == 0 || abi.decode(returndata, (bool)), TRANSFER_FROM_RETURNED_FALSE);
    }
}
