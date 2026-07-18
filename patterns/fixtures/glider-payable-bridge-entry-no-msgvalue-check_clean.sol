pragma solidity ^0.8.0;

contract BridgeClean {
    address public relayer;

    function initiateTransfer(address to, uint256 amount) external payable {
        uint256 fee = 0.01 ether;
        address ops = address(0x1234);
        
        require(msg.value == amount + fee, "bad msg.value");
        
        (bool ok1, ) = to.call{value: amount}("");
        require(ok1, "send failed");
        
        (bool ok2, ) = ops.call{value: fee}("");
        require(ok2, "fee failed");
    }
}