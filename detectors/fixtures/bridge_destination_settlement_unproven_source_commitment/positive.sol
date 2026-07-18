pragma solidity ^0.8.20;

contract BridgeDestinationSettlementPositive {
    mapping(bytes32 => bool) public processedTransfers;
    mapping(address => uint256) public escrowCredit;

    function finalizeBridgeERC20(
        address recipient,
        uint256 amount,
        bytes32 transferId
    ) external {
        require(!processedTransfers[transferId], "already finalized");
        processedTransfers[transferId] = true;

        escrowCredit[recipient] += amount;
    }
}
