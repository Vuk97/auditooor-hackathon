pragma solidity ^0.8.0;

contract RelayerBridge {
    address public trustedEndpoint;
    mapping(address => uint256) public balances;

    constructor() {
        trustedEndpoint = address(0x1234);
    }

    function lzReceive(uint16 srcChain, bytes calldata payload, uint64 nonce) external {
        require(msg.sender == trustedEndpoint, "untrusted relayer");
        (address user, uint256 amount) = abi.decode(payload, (address, uint256));
        balances[user] += amount;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}