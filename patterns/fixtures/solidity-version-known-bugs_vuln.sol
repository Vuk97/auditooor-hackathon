// SPDX-License-Identifier: MIT
// VULN: pragma pins to 0.8.13, which is on the known-bugs list
// (inline-assembly storage miscompilation, SPF-2022-0003).
pragma solidity 0.8.13;

contract VulnPragma {
    uint256 public value;

    constructor() {
        value = 1;
    }

    function set(uint256 v) external {
        // An inline-assembly write here would hit the 0.8.13 storage bug
        // under the right optimizer path. Flagging the pragma surfaces
        // the class of risk regardless of function body.
        assembly {
            sstore(value.slot, v)
        }
    }
}
