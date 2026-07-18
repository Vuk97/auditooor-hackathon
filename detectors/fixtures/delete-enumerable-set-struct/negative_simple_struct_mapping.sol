// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimpleStructDeleteNegative {
    struct ResponseReceipt {
        address relayer;
        uint256 amount;
    }

    mapping(bytes32 => ResponseReceipt) private _responseReceipts;

    function clear(bytes32 id) external {
        delete _responseReceipts[id];
    }
}
