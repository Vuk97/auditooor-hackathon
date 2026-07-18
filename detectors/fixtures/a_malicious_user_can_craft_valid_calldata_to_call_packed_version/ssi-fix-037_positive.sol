// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

library ILiFi {
    struct BridgeData {
        bytes32 transactionId;
        address receiver;
        address sendingAssetId;
        uint256 minAmount;
        uint256 destinationChainId;
        bool hasSourceSwaps;
        bool hasDestinationCall;
    }
}

contract LiFiPackedEndpointValidatorPositive {
    error InvalidSelector();

    bytes4 private constant HOP_L2_NATIVE_PACKED =
        bytes4(keccak256("startBridgeTokensViaHopL2NativePacked(bytes32,address,uint256,uint256)"));
    bytes4 private constant CBRIDGE_NATIVE_PACKED =
        bytes4(keccak256("startBridgeTokensViaCBridgeNativePacked(bytes32,address,uint256,uint64)"));

    function validateTxData(bytes calldata txData) external pure returns (address receiver, uint256 minAmount) {
        if (txData.length < 4) {
            revert InvalidSelector();
        }

        bytes4 selector = bytes4(txData[:4]);
        if (
            selector == HOP_L2_NATIVE_PACKED
                || selector == CBRIDGE_NATIVE_PACKED
                || selector == this.startBridgeTokensViaHopL2NativePacked.selector
                || selector == this.startBridgeTokensViaCBridgeNativePacked.selector
        ) {
            ILiFi.BridgeData memory bridgeData = abi.decode(txData[4:], (ILiFi.BridgeData));
            return (bridgeData.receiver, bridgeData.minAmount);
        }

        revert InvalidSelector();
    }

    function startBridgeTokensViaHopL2NativePacked(
        bytes32 transactionId,
        address receiver,
        uint256 amount,
        uint256 destinationChainId
    ) external pure returns (bytes32, address, uint256, uint256) {
        return (transactionId, receiver, amount, destinationChainId);
    }

    function startBridgeTokensViaCBridgeNativePacked(
        bytes32 transactionId,
        address receiver,
        uint256 amount,
        uint64 destinationChainId
    ) external pure returns (bytes32, address, uint256, uint64) {
        return (transactionId, receiver, amount, destinationChainId);
    }
}
