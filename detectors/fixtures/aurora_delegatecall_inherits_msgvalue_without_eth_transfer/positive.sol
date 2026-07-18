pragma solidity ^0.8.24;

contract AuroraBridgeExitPrecompile {
    event ExitToNear(address indexed sender, address indexed recipient, uint256 amount);

    function withdrawToNear(address recipient) external payable {
        require(msg.value > 0, "zero");
        emit ExitToNear(msg.sender, recipient, msg.value);
    }
}
