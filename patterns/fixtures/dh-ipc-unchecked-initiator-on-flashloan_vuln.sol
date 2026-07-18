// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IPCFlashInitiatorVuln {
    address public pool;
    function executeOperation(address[] calldata, uint256[] calldata, uint256[] calldata, address initiator, bytes calldata params) external returns (bool) {
        require(msg.sender == pool, "pool only");
        (address victim, uint256 amt) = abi.decode(params, (address, uint256));
        // VULN: no check that the flashloan was self-initiated.
        _doSwap(victim, amt);
        return true;
    }
    function _doSwap(address, uint256) internal {}
}
