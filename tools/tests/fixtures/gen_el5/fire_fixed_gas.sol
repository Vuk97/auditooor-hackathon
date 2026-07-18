// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// fixed-gas external call: hard-coded gas whose sufficiency is assumed.
contract Notifier {
    address public sink;
    function notify(bytes calldata data) external {
        (bool ok, ) = sink.call{value: 0, gas: 10000}(data);  // <-- fixed-gas-call
        require(ok);
    }
}
