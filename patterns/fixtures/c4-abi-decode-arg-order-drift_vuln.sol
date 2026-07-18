// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BasinDecoderVuln {
    uint256 public reserves;
    uint8 public decimals0;
    uint8 public decimals1;
    address public caller;

    /// VULN: wide decode tuple mixes uint256/uint8/address — prone to arg-order drift.
    function setParams(bytes calldata data) external {
        (uint256 r, address c, uint8 d0, uint8 d1) = abi.decode(data, (uint256, address, uint8, uint8));
        reserves = r;
        caller = c;
        decimals0 = d0;
        decimals1 = d1;
    }
}
