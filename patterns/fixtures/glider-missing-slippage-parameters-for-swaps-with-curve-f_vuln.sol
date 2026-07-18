// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GliderMissingSlippageParametersForSwapsWithCurveFVuln {
    function exchange(address) internal {}
    function targetFn() external {
        exchange(msg.sender);
    }
}
