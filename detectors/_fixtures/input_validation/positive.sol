// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library Enum {
    enum Operation {
        Call,
        DelegateCall
    }
}

interface ISafe {
    function setFallbackHandler(address handler) external;
}

interface IGuard {
    function checkTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures,
        address msgSender
    ) external;
}

contract VulnerableRentalSafeGuard is IGuard {
    bytes4 private constant SET_FALLBACK_HANDLER_SELECTOR =
        bytes4(keccak256("setFallbackHandler(address)"));
    address public immutable safe;

    constructor(address safe_) {
        safe = safe_;
    }

    function checkTransaction(
        address to,
        uint256,
        bytes calldata data,
        Enum.Operation operation,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes calldata,
        address
    ) external override {
        require(to == safe, "wrong-safe");
        require(operation == Enum.Operation.Call, "delegatecall-blocked");

        if (data.length >= 4) {
            bytes4 selector = bytes4(data[:4]);
            if (selector == SET_FALLBACK_HANDLER_SELECTOR) {
                // Vulnerable: recognizes setFallbackHandler(address) but never
                // decodes or validates the caller-supplied handler address.
            }
        }
    }
}
