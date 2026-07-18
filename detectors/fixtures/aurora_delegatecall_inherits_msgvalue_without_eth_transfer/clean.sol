pragma solidity ^0.8.24;

contract AuroraBridgeExitPrecompile {
    uint8 private constant Call = 0;
    uint8 private constant DelegateCall = 1;

    event ExitToNear(address indexed sender, address indexed recipient, uint256 amount);

    function _callType() internal pure returns (uint8) {
        return Call;
    }

    function withdrawToNear(address recipient) external payable {
        require(msg.value > 0, "zero");
        uint8 callType = _callType();
        require(callType != DelegateCall, "delegatecall-disabled");
        emit ExitToNear(msg.sender, recipient, msg.value);
    }
}
