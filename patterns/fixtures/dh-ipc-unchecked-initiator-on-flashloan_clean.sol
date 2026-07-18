// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IPCFlashInitiatorClean {
    address public pool;
    function executeOperation(address[] calldata, uint256[] calldata, uint256[] calldata, address initiator, bytes calldata params) external returns (bool) {
        require(msg.sender == pool, "pool only");
        require(initiator == address(this), "bad initiator");
        (address victim, uint256 amt) = abi.decode(params, (address, uint256));
        _doSwap(victim, amt);
        return true;
    }
    function _doSwap(address, uint256) internal {}
}
