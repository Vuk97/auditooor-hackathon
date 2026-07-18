// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Caller {
    function doTransfer(address to, uint256 amount) external returns (bool) {
        bool ok = validateAmount(amount);
        require(ok, "bad amount");
        return true;
    }
}
