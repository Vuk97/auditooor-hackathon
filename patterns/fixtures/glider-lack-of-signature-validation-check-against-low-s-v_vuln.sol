// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GliderLackOfSignatureValidationCheckAgainstLowSVVuln {
    function ecrecover(address) internal {}
    function targetFn() external {
        ecrecover(msg.sender);
    }
}
