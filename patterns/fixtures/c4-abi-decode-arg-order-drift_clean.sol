// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BasinDecoderClean {
    struct Params { uint256 reserves; address caller; uint8 decimals0; uint8 decimals1; }

    uint256 public reserves;
    uint8 public decimals0;
    uint8 public decimals1;
    address public caller;

    function setParams(bytes calldata data) external {
        Params memory p = abi.decode(data, (Params));
        reserves = p.reserves;
        caller = p.caller;
        decimals0 = p.decimals0;
        decimals1 = p.decimals1;
    }
}
