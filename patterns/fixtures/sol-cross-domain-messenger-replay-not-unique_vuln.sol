// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CrossDomainMessengerVuln {
    function relayMessage(address target, bytes calldata data) external returns (bool) {
        (bool ok, ) = target.call(data);
        return ok;
    }
}
