// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: fixed version of SafeTransferLib — checks code.length before low-level call.
// Source: morpho-org/morpho-blue@a4cb34b (cantina audit fix)

contract Fix {
    string internal constant NO_CODE = "no code";
    string internal constant TRANSFER_REVERTED = "transfer reverted";
    string internal constant TRANSFER_RETURNED_FALSE = "transfer returned false";
    string internal constant TRANSFER_FROM_REVERTED = "transferFrom reverted";
    string internal constant TRANSFER_FROM_RETURNED_FALSE = "transferFrom returned false";

    // FIXED: revert if token has no deployed code
    function safeTransfer(address token, address to, uint256 value) external {
        require(address(token).code.length > 0, NO_CODE);
        (bool success, bytes memory returndata) =
            token.call(abi.encodeWithSignature("transfer(address,uint256)", to, value));
        require(success, TRANSFER_REVERTED);
        require(returndata.length == 0 || abi.decode(returndata, (bool)), TRANSFER_RETURNED_FALSE);
    }

    // FIXED: same guard for transferFrom
    function safeTransferFrom(address token, address from, address to, uint256 value) external {
        require(address(token).code.length > 0, NO_CODE);
        (bool success, bytes memory returndata) =
            token.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", from, to, value));
        require(success, TRANSFER_FROM_REVERTED);
        require(returndata.length == 0 || abi.decode(returndata, (bool)), TRANSFER_FROM_RETURNED_FALSE);
    }
}
